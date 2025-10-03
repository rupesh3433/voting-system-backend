import os
import base64
from tempfile import NamedTemporaryFile
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv("ASTRA_DB_CLIENT_ID")
CLIENT_SECRET = os.getenv("ASTRA_DB_CLIENT_SECRET")
BUNDLE_B64 = os.getenv("ASTRA_DB_BUNDLE_B64")

if not CLIENT_ID or not CLIENT_SECRET or not BUNDLE_B64:
    raise ValueError("Missing Astra DB credentials or bundle in environment variables.")

# Decode base64 into a temporary file
temp_bundle = NamedTemporaryFile(suffix=".zip", delete=False)
try:
    temp_bundle.write(base64.b64decode(BUNDLE_B64))
    temp_bundle.flush()
    temp_bundle.close()  # ✅ Close it so Windows allows reopening

    cloud_config = {'secure_connect_bundle': temp_bundle.name}
    auth_provider = PlainTextAuthProvider(username=CLIENT_ID, password=CLIENT_SECRET)

    cluster = Cluster(cloud=cloud_config, auth_provider=auth_provider)
    session = cluster.connect()
    print("✅ Connected to Astra DB!")

    # Test query
    row = session.execute("SELECT release_version FROM system.local").one()
    print("Astra DB release version:", row[0] if row else "Unknown")
finally:
    os.unlink(temp_bundle.name)  # Clean up the temp file




