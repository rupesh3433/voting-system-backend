import os
import uuid
import hashlib
import datetime
import bcrypt
import jwt
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import boto3
import base64
from tempfile import NamedTemporaryFile

# ---------------- Cassandra Setup ----------------
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider

# ---------------- Load env ----------------
load_dotenv()

# ---------------- Flask App ----------------
app = Flask(__name__)
CORS(app)

# ---------------- Connect to Astra DB ----------------
session = None
try:
    # Use client credentials directly from .env
    CLIENT_ID = os.getenv("ASTRA_DB_CLIENT_ID")
    CLIENT_SECRET = os.getenv("ASTRA_DB_CLIENT_SECRET")
    ASTRA_DB_KEYSPACE = os.getenv("ASTRA_DB_KEYSPACE")
    
    # Decode secure bundle from base64
    ASTRA_DB_BUNDLE_B64 = os.getenv("ASTRA_DB_BUNDLE_B64")
    bundle_bytes = base64.b64decode(ASTRA_DB_BUNDLE_B64)
    
    # Create temporary secure bundle file
    with NamedTemporaryFile(suffix='.zip', delete=False) as tmp_bundle:
        tmp_bundle.write(bundle_bytes)
        tmp_bundle_path = tmp_bundle.name
    
    cloud_config = {'secure_connect_bundle': tmp_bundle_path}
    auth_provider = PlainTextAuthProvider(username=CLIENT_ID, password=CLIENT_SECRET)

    cluster = Cluster(cloud=cloud_config, auth_provider=auth_provider)
    session = cluster.connect(ASTRA_DB_KEYSPACE)

    row = session.execute("SELECT release_version FROM system.local").one()
    if row:
        print("Connected to Astra DB, release version:", row[0])
    else:
        print("Connection to Astra DB failed.")
    
    # Clean up temporary file
    os.unlink(tmp_bundle_path)
    
except Exception as e:
    print("WARNING: Could not connect to AstraDB:", e)
    session = None

# ---------------- S3 client ----------------
s3_client = boto3.client(
    's3',
    region_name=os.getenv("S3_REGION"),
    aws_access_key_id=os.getenv("S3_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("S3_SECRET_ACCESS_KEY")
)

# ---------------- Helpers ----------------
def upload_file_to_s3(file_obj, key):
    try:
        file_obj.seek(0)
    except Exception:
        pass
    s3_client.upload_fileobj(file_obj, os.getenv("S3_BUCKET"), key)
    return f"https://{os.getenv('S3_BUCKET')}.s3.{os.getenv('S3_REGION')}.amazonaws.com/{key}"

def hash_fingerprint(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def generate_jwt(payload):
    payload_copy = payload.copy()
    payload_copy["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=12)
    token = jwt.encode(payload_copy, os.getenv("JWT_SECRET"), algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode()
    return token

def decode_jwt(token):
    try:
        return jwt.decode(token, os.getenv("JWT_SECRET"), algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def get_user_from_token():
    auth_header = request.headers.get("Authorization")
    if not auth_header or " " not in auth_header:
        return None
    token = auth_header.split(" ")[1].strip()
    return decode_jwt(token)

def is_admin():
    user = get_user_from_token()
    return bool(user and user.get("is_admin", False))

def log_audit(actor_id, action, details=""):
    if not session:
        return
    try:
        session.execute(
            "INSERT INTO audit_logs (log_id, actor_id, action, details, created_at) VALUES (%s,%s,%s,%s,%s)",
            (uuid.uuid4(), uuid.UUID(str(actor_id)), action, details, datetime.datetime.utcnow())
        )
    except Exception as e:
        print("Audit log failed:", e)


# ---------------- Auth Routes ----------------
@app.route("/api/auth/register", methods=["POST"])
def register():
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    data = request.json or {}
    if not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({"error": "email, password and name required"}), 400

    # Normalize email
    email = data['email'].strip().lower()
    password_hash = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
    user_id = uuid.uuid4()
    try:
        session.execute(
            "INSERT INTO users (user_id,email,password_hash,name,is_admin,created_at) VALUES (%s,%s,%s,%s,%s,%s)",
            (user_id, email, password_hash, data['name'], False, datetime.datetime.utcnow())
        )
    except Exception as e:
        return jsonify({"error": "DB insert failed", "detail": str(e)}), 500
    return jsonify({"message":"User registered", "user_id": str(user_id)}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    data = request.json or {}
    if not data.get('email') or not data.get('password'):
        return jsonify({"error": "email and password required"}), 400

    # Normalize email - REMOVED ALLOW FILTERING since we have index
    email = data['email'].strip().lower()
    
    try:
        user_row = session.execute(
            "SELECT user_id, password_hash, is_admin FROM users WHERE email=%s",
            (email,)
        ).one()
    except Exception as e:
        print(f"Database error during login: {e}")
        return jsonify({"error": "Database query failed"}), 500

    if not user_row:
        return jsonify({"error":"Invalid email or password"}), 401

    if not bcrypt.checkpw(data['password'].encode(), user_row.password_hash.encode()):
        return jsonify({"error":"Invalid email or password"}), 401

    token = generate_jwt({"user_id": str(user_row.user_id), "is_admin": user_row.is_admin})
    return jsonify({"token": token})

@app.route("/api/auth/me", methods=["GET"])
def get_current_user():
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    user = get_user_from_token()
    if not user:
        return jsonify({"error":"Unauthorized"}), 401
    user_row = session.execute(
        "SELECT user_id,email,name,is_admin FROM users WHERE user_id=%s",
        (uuid.UUID(user["user_id"]),)
    ).one()
    if not user_row:
        return jsonify({"error":"User not found"}), 404
    return jsonify({
        "user_id": str(user_row.user_id),
        "email": user_row.email,
        "name": user_row.name,
        "is_admin": user_row.is_admin
    })


# ---------------- Voter Routes ----------------
@app.route("/api/voters/register", methods=["POST"])
def register_voter():
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    user = get_user_from_token()
    if not user:
        return jsonify({"error":"Unauthorized"}), 401

    epic_id = request.form.get('epic_id')
    dob = request.form.get('dob')
    address = request.form.get('address','')
    photo = request.files.get('photo')
    fingerprint = request.files.get('fingerprint')
    if not all([epic_id, dob, photo, fingerprint]):
        return jsonify({"error":"epic_id, dob, photo and fingerprint required"}), 400

    photo_url = upload_file_to_s3(photo, f"photos/{uuid.uuid4()}.jpg")
    fingerprint_hash = hash_fingerprint(fingerprint.read())
    voter_id = uuid.uuid4()

    try:
        session.execute(
            """INSERT INTO voters (voter_id,user_id,epic_id,dob,address,photo_url,fingerprint_hash,approved,created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (voter_id, uuid.UUID(user["user_id"]), epic_id, dob, address, photo_url, fingerprint_hash, False, datetime.datetime.utcnow())
        )
    except Exception as e:
        return jsonify({"error":"DB insert failed","detail": str(e)}), 500

    log_audit(user["user_id"], "voter_register", f"Voter ID: {voter_id}")
    return jsonify({"message":"Voter registered, pending approval","voter_id": str(voter_id)}), 201

@app.route("/api/admin/pending-voters", methods=["GET"])
def list_pending_voters():
    if not session:
        return jsonify([]), 200  # return empty list if DB not connected
    if not is_admin():
        return jsonify({"error": "Admin access required"}), 403
    try:
        rows = session.execute(
            "SELECT voter_id, user_id, epic_id, dob, address, photo_url, approved, created_at "
            "FROM voters WHERE approved=false"
        )
        voters = []
        for r in rows:
            voters.append({
                "voter_id": str(r.voter_id),
                "user_id": str(r.user_id),
                "epic_id": r.epic_id,
                "dob": r.dob,
                "address": r.address,
                "photo_url": r.photo_url,
                "approved": r.approved,
                "created_at": r.created_at.isoformat() if r.created_at else None
            })
        return jsonify(voters), 200
    except Exception:
        return jsonify([]), 200  # return empty list if query fails


@app.route("/api/voters/approved", methods=["GET"])
def get_approved_voters():
    if not session:
        return jsonify({"error": "Database not connected"}), 500

    try:
        rows = session.execute(
            "SELECT voter_id, user_id, epic_id, dob, address, photo_url, created_at FROM voters WHERE approved=true"
        )

        voters = []
        for row in rows:
            voters.append({
                "voter_id": str(row.voter_id),
                "user_id": str(row.user_id),
                "epic_id": row.epic_id,
                "dob": row.dob,
                "address": row.address,
                "photo_url": row.photo_url,
                "created_at": row.created_at.isoformat() if row.created_at else None
            })

        return jsonify(voters), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch approved voters", "detail": str(e)}), 500


@app.route("/api/voters/<voter_id>/approve", methods=["POST"])
def approve_voter(voter_id):
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    if not is_admin():
        return jsonify({"error":"Admin access required"}), 403
    try:
        session.execute("UPDATE voters SET approved=true WHERE voter_id=%s", (uuid.UUID(voter_id),))
    except Exception as e:
        return jsonify({"error":"DB update failed","detail": str(e)}), 500
    log_audit(get_user_from_token()["user_id"], "approve_voter", f"Voter ID: {voter_id}")
    return jsonify({"message":"Voter approved"}), 200

@app.route("/api/voters/<voter_id>/reject", methods=["POST"])
def reject_voter(voter_id):
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    if not is_admin():
        return jsonify({"error":"Admin access required"}), 403
    try:
        session.execute("DELETE FROM voters WHERE voter_id=%s", (uuid.UUID(voter_id),))
    except Exception as e:
        return jsonify({"error":"DB delete failed","detail": str(e)}), 500
    log_audit(get_user_from_token()["user_id"], "reject_voter", f"Voter ID: {voter_id}")
    return jsonify({"message":"Voter rejected and removed"}), 200


@app.route("/api/voters/my-status", methods=["GET"])
def my_voter_status():
    if not session:
        return jsonify({"error": "Database not connected"}), 500

    user = get_user_from_token()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        row = session.execute(
            "SELECT voter_id, approved, epic_id, dob, address, photo_url, created_at "
            "FROM voters WHERE user_id=%s",
            (uuid.UUID(user["user_id"]),)
        ).one()

        # ✅ Case 1: User has never registered as a voter
        if not row:
            return jsonify({
                "registered": False,
                "status": "not_registered"
            }), 200

        # ✅ Case 2: User registered but waiting approval
        if not row.approved:
            return jsonify({
                "registered": True,
                "voter_id": str(row.voter_id),
                "approved": False,
                "status": "pending",
                "epic_id": row.epic_id,
                "dob": row.dob,
                "address": row.address,
                "photo_url": row.photo_url,
                "created_at": row.created_at.isoformat() if row.created_at else None
            }), 200

        # ✅ Case 3: User is approved
        return jsonify({
            "registered": True,
            "voter_id": str(row.voter_id),
            "approved": True,
            "status": "approved",
            "epic_id": row.epic_id,
            "dob": row.dob,
            "address": row.address,
            "photo_url": row.photo_url,
            "created_at": row.created_at.isoformat() if row.created_at else None
        }), 200

    except Exception as e:
        return jsonify({
            "error": "Failed to fetch voter status",
            "detail": str(e)
        }), 500



# ---------------- Election Routes---------------
@app.route("/api/elections", methods=["POST"])
def create_election():
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    if not is_admin():
        return jsonify({"error":"Admin access required"}), 403
    data = request.json or {}
    if not data.get('title') or not data.get('start_at') or not data.get('end_at'):
        return jsonify({"error":"title, start_at and end_at required"}), 400
    election_id = uuid.uuid4()
    try:
        session.execute(
            """INSERT INTO elections (election_id,title,description,start_at,end_at,published,created_by,created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (election_id, data['title'], data.get('description',''), data['start_at'], data['end_at'], False,
             uuid.UUID(get_user_from_token()["user_id"]), datetime.datetime.utcnow())
        )
    except Exception as e:
        return jsonify({"error":"DB insert failed","detail": str(e)}), 500
    log_audit(get_user_from_token()["user_id"], "create_election", f"Election ID: {election_id}")
    return jsonify({"message":"Election created","election_id": str(election_id)}), 201

@app.route("/api/elections/<election_id>/candidates", methods=["POST"])
def add_candidate(election_id):
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    if not is_admin():
        return jsonify({"error":"Admin access required"}), 403
    data = request.form
    photo = request.files.get('photo')
    if not data.get('name') or not data.get('party') or not photo:
        return jsonify({"error":"name, party and photo required"}), 400
    photo_url = upload_file_to_s3(photo, f"candidates/{uuid.uuid4()}.jpg")
    candidate_id = uuid.uuid4()
    try:
        session.execute(
            "INSERT INTO candidates_by_election (election_id,candidate_id,name,party,photo_url) VALUES (%s,%s,%s,%s,%s)",
            (uuid.UUID(election_id), candidate_id, data['name'], data['party'], photo_url)
        )
    except Exception as e:
        return jsonify({"error":"DB insert failed","detail": str(e)}), 500
    log_audit(get_user_from_token()["user_id"], "add_candidate", f"Election: {election_id}, Candidate: {candidate_id}")
    return jsonify({"message":"Candidate added","candidate_id": str(candidate_id)}), 201

@app.route("/api/elections/<election_id>/publish", methods=["POST"])
def publish_election(election_id):
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    if not is_admin():
        return jsonify({"error":"Admin access required"}), 403
    try:
        session.execute("UPDATE elections SET published=true WHERE election_id=%s", (uuid.UUID(election_id),))
    except Exception as e:
        return jsonify({"error":"DB update failed","detail": str(e)}), 500
    log_audit(get_user_from_token()["user_id"], "publish_election", f"Election ID: {election_id}")
    return jsonify({"message":"Election published"}), 200

@app.route("/api/elections/<election_id>/unpublish", methods=["POST"])
def unpublish_election(election_id):
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    if not is_admin():
        return jsonify({"error":"Admin access required"}), 403
    try:
        session.execute("UPDATE elections SET published=false WHERE election_id=%s", (uuid.UUID(election_id),))
    except Exception as e:
        return jsonify({"error":"DB update failed","detail": str(e)}), 500
    log_audit(get_user_from_token()["user_id"], "unpublish_election", f"Election ID: {election_id}")
    return jsonify({"message":"Election unpublished"}), 200

@app.route("/api/elections/<election_id>/vote", methods=["POST"])
def cast_vote(election_id):
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    user = get_user_from_token()
    if not user:
        return jsonify({"error":"Unauthorized"}), 401
    data = request.json or {}
    if not data.get('voter_id') or not data.get('candidate_id'):
        return jsonify({"error":"voter_id and candidate_id required"}), 400

    voter_id = data['voter_id']
    candidate_id = data['candidate_id']

    # ✅ FIX: Verify the voter belongs to the current user AND is approved
    voter = session.execute(
        "SELECT approved, user_id FROM voters WHERE voter_id=%s", 
        (uuid.UUID(voter_id),)
    ).one()
    
    if not voter:
        return jsonify({"error":"Voter not found"}), 404
    
    if str(voter.user_id) != user["user_id"]:
        return jsonify({"error":"Voter does not belong to current user"}), 403
        
    if not voter.approved:
        return jsonify({"error":"Voter not approved"}), 403

    election = session.execute(
        "SELECT start_at,end_at,published FROM elections WHERE election_id=%s", 
        (uuid.UUID(election_id),)
    ).one()
    
    now = datetime.datetime.utcnow()
    if not election or not election.published or not (election.start_at <= now <= election.end_at):
        return jsonify({"error":"Election not active"}), 403

    # Check if already voted
    existing_vote = session.execute(
        "SELECT * FROM votes_by_voter WHERE election_id=%s AND voter_id=%s", 
        (uuid.UUID(election_id), uuid.UUID(voter_id))
    ).one()
    
    if existing_vote:
        return jsonify({"error":"Vote already cast"}), 400

    vote_id = uuid.uuid4()
    try:
        session.execute(
            """INSERT INTO votes_by_voter (election_id,voter_id,vote_id,candidate_id,cast_at)
               VALUES (%s,%s,%s,%s,%s)""",
            (uuid.UUID(election_id), uuid.UUID(voter_id), vote_id, uuid.UUID(candidate_id), now)
        )
        
        session.execute(
            "INSERT INTO votes_by_election (election_id,vote_id,voter_id,candidate_id,cast_at,vote_hash) VALUES (%s,%s,%s,%s,%s,%s)",
            (uuid.UUID(election_id), vote_id, uuid.UUID(voter_id), uuid.UUID(candidate_id), now, str(uuid.uuid4()))
        )
        
        session.execute(
            "UPDATE candidate_counters SET vote_count = vote_count + 1 WHERE election_id=%s AND candidate_id=%s",
            (uuid.UUID(election_id), uuid.UUID(candidate_id))
        )
    except Exception as e:
        return jsonify({"error":"DB operation failed","detail": str(e)}), 500

    log_audit(user["user_id"], "cast_vote", f"Election: {election_id}, Voter: {voter_id}, Candidate: {candidate_id}")
    return jsonify({"message":"Vote cast successfully"}), 201

@app.route("/api/elections/<election_id>/live-results", methods=["GET"])
def live_results(election_id):
    user = get_user_from_token()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # Fetch candidates for this election from Cassandra
    try:
        candidates_rows = session.execute(
            "SELECT candidate_id, name, party, photo_url FROM candidates_by_election WHERE election_id=%s",
            (uuid.UUID(election_id),)
        )

        candidates_list = []
        counts = {}

        for c in candidates_rows:
            # Count votes per candidate
            vote_count_row = session.execute(
                "SELECT vote_count FROM candidate_counters WHERE election_id=%s AND candidate_id=%s",
                (uuid.UUID(election_id), c.candidate_id)
            ).one()
            vote_count = vote_count_row.vote_count if vote_count_row else 0

            candidates_list.append({
                "candidate_id": str(c.candidate_id),
                "name": c.name,
                "party": c.party,
                "photo_url": c.photo_url
            })
            counts[str(c.candidate_id)] = vote_count

        return jsonify({"candidates": candidates_list, "counts": counts}), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch live results", "detail": str(e)}), 500


# ---------------- Candidate Routes ----------------
@app.route("/api/candidates", methods=["GET"])
def get_candidates():
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    try:
        rows = session.execute("SELECT * FROM candidates_by_election")
        candidates = []
        for r in rows:
            candidate_dict = {
                "candidate_id": str(r.candidate_id),
                "election_id": str(r.election_id),
                "name": r.name,
                "party": r.party,
                "photo_url": r.photo_url,
                "created_at": r.created_at.isoformat() if hasattr(r, 'created_at') and r.created_at else None
            }
            candidates.append(candidate_dict)
        return jsonify(candidates), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch candidates", "detail": str(e)}), 500

# ---------------- Dashboard / Public ----------------
@app.route("/api/elections", methods=["GET"])
def list_elections():
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    try:
        rows = session.execute("SELECT * FROM elections")
        now = datetime.datetime.utcnow()
        elections = []
        for r in rows:
            status = "upcoming"
            try:
                if r.start_at <= now <= r.end_at:
                    status = "ongoing"
                elif r.end_at < now:
                    status = "past"
            except Exception:
                pass
            
            election_dict = {
                "election_id": str(r.election_id),
                "title": r.title,
                "description": r.description,
                "start_at": r.start_at.isoformat() if r.start_at else None,
                "end_at": r.end_at.isoformat() if r.end_at else None,
                "published": r.published,
                "created_by": str(r.created_by) if r.created_by else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "status": status
            }
            elections.append(election_dict)
        return jsonify(elections), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch elections", "detail": str(e)}), 500

@app.route("/api/elections/<election_id>", methods=["GET"])
def election_detail(election_id):
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    try:
        candidates = session.execute("SELECT * FROM candidates_by_election WHERE election_id=%s", (uuid.UUID(election_id),))
        candidates_list = []
        for c in candidates:
            candidate_dict = {
                "candidate_id": str(c.candidate_id),
                "election_id": str(c.election_id),
                "name": c.name,
                "party": c.party,
                "photo_url": c.photo_url,
                "created_at": c.created_at.isoformat() if hasattr(c, 'created_at') and c.created_at else None
            }
            candidates_list.append(candidate_dict)
        
        counters = session.execute("SELECT * FROM candidate_counters WHERE election_id=%s", (uuid.UUID(election_id),))
        counts = {str(c.candidate_id): c.vote_count for c in counters}
        
        return jsonify({"candidates": candidates_list, "counts": counts}), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch election details", "detail": str(e)}), 500

@app.route("/api/elections/<election_id>/votes/latest", methods=["GET"])
def latest_votes(election_id):
    if not session:
        return jsonify({"error": "Database not connected"}), 500
    try:
        counters = session.execute("SELECT * FROM candidate_counters WHERE election_id=%s", (uuid.UUID(election_id),))
        counts = {str(c.candidate_id): c.vote_count for c in counters}
        return jsonify(counts), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch vote counts", "detail": str(e)}), 500

# Health check endpoint
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "database_connected": session is not None}), 200

# ---------------- Run App ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)