import os
from polar_sdk import Polar
from dotenv import load_dotenv

load_dotenv()

def test_connection():
    token = os.environ.get("POLAR_ACCESS_TOKEN")
    polar = Polar(access_token=token)

    try:
        # 1. Fetch Organization List
        print("📡 Fetching Organizations...")
        orgs_response = polar.organizations.list()
        
        # Accessing the list from the response object
        orgs = orgs_response.result.items 
        
        if not orgs:
            print("⚠️ Connected, but found 0 organizations. Is your product created?")
            return

        for org in orgs:
            print(f"🏢 Found Org: {org.name} (ID: {org.id})")
            
            # 2. List Products for this Org
            print(f"📦 Fetching products for {org.name}...")
            products = polar.products.list(organization_id=org.id)
            for p in products.result.items:
                print(f"   - Product: {p.name} (ID: {p.id})")

    except Exception as e:
        print(f"❌ Connection Failed: {str(e)}")

if __name__ == "__main__":
    test_connection()