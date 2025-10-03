# create_schema.py
import os
import sys
import base64
from tempfile import NamedTemporaryFile
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from dotenv import load_dotenv

# ---------------- Load environment ----------------
load_dotenv()

CLIENT_ID = os.getenv("ASTRA_DB_CLIENT_ID")
CLIENT_SECRET = os.getenv("ASTRA_DB_CLIENT_SECRET")
BUNDLE_B64 = os.getenv("ASTRA_DB_BUNDLE_B64")
KEYSPACE = os.getenv("ASTRA_DB_KEYSPACE")

if not CLIENT_ID or not CLIENT_SECRET or not BUNDLE_B64 or not KEYSPACE:
    print("Missing Astra DB credentials, bundle, or keyspace. Exiting.")
    sys.exit(1)

# ---------------- Decode base64 bundle into a temporary file ----------------
temp_bundle = NamedTemporaryFile(suffix=".zip", delete=False)
try:
    temp_bundle.write(base64.b64decode(BUNDLE_B64))
    temp_bundle.flush()
    temp_bundle.close()  # ✅ Important for Windows to reopen

    # ---------------- Connect to Astra DB ----------------
    cloud_config = {'secure_connect_bundle': temp_bundle.name}
    auth_provider = PlainTextAuthProvider(username=CLIENT_ID, password=CLIENT_SECRET)

    try:
        cluster = Cluster(cloud=cloud_config, auth_provider=auth_provider)
        session = cluster.connect()
        session.set_keyspace(KEYSPACE)
        print(f"✅ Connected to Astra DB keyspace: {KEYSPACE}")
    except Exception as e:
        print("❌ Failed to connect to Astra DB:", e)
        sys.exit(1)

    # ---------------- DDL statements ----------------
    ddls = [
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id uuid PRIMARY KEY,
            email text,
            password_hash text,
            name text,
            is_admin boolean,
            created_at timestamp
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)",
        """
        CREATE TABLE IF NOT EXISTS voters (
            voter_id uuid PRIMARY KEY,
            user_id uuid,
            epic_id text,
            dob text,
            address text,
            photo_url text,
            fingerprint_hash text,
            approved boolean,
            created_at timestamp
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_voters_user_id ON voters (user_id)",
        "CREATE INDEX IF NOT EXISTS idx_voters_approved ON voters (approved)",
        "CREATE INDEX IF NOT EXISTS idx_voters_epic_id ON voters (epic_id)",
        """
        CREATE TABLE IF NOT EXISTS elections (
            election_id uuid PRIMARY KEY,
            title text,
            description text,
            start_at timestamp,
            end_at timestamp,
            published boolean,
            created_by uuid,
            created_at timestamp
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_elections_published ON elections (published)",
        """
        CREATE TABLE IF NOT EXISTS candidates_by_election (
            election_id uuid,
            candidate_id uuid,
            name text,
            party text,
            photo_url text,
            created_at timestamp,
            PRIMARY KEY (election_id, candidate_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS candidate_counters (
            election_id uuid,
            candidate_id uuid,
            vote_count counter,
            PRIMARY KEY (election_id, candidate_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS votes_by_voter (
            election_id uuid,
            voter_id uuid,
            vote_id uuid,
            candidate_id uuid,
            cast_at timestamp,
            PRIMARY KEY ((election_id, voter_id), vote_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS votes_by_election (
            election_id uuid,
            vote_id uuid,
            voter_id uuid,
            candidate_id uuid,
            cast_at timestamp,
            vote_hash text,
            PRIMARY KEY (election_id, vote_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id uuid PRIMARY KEY,
            actor_id uuid,
            action text,
            details text,
            created_at timestamp
        )
        """
    ]

    # ---------------- Execute DDLs ----------------
    for ddl in ddls:
        print("Executing:", ddl.strip().splitlines()[0])
        try:
            session.execute(ddl)
        except Exception as e:
            print("❌ Failed:", e)

    print("✅ Schema creation finished.")
finally:
    os.unlink(temp_bundle.name)  # Clean up temp file
