import os
import httpx
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    db = SessionLocal()
    try:
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"ERROR: User with email {customer_email} not found in database.")
            return None
            
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        if not token or not product_id:
            print("ERROR: Missing POLAR_ACCESS_TOKEN or POLAR_PRODUCT_ID in environment.")
            return None

        # Clean whitespace from IDs (common issue with environment variables)
        product_id = product_id.strip()

        # 1. NEW ENDPOINT (Standard for 2026)
        url = "https://api.polar.sh/v1/checkouts/"
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # 2. UPDATED PAYLOAD STRUCTURE
        payload = {
            "products": [product_id], 
            "success_url": "https://metria.dev/dashboard?payment=success",
            "return_url": "https://metria.dev/dashboard",
            "customer_email": customer_email,
            "allow_discount_codes": True,
            "metadata": {
                "user_id": str(user.id),  # Ensure this is a string
                "email": customer_email
            }
        }

        print(f"DEBUG: Calling Polar v1/checkouts for {customer_email}...")
        
        with httpx.Client() as client:
            response = client.post(url, json=payload, headers=headers, timeout=15.0)
            
        if response.status_code in [200, 201]:
            data = response.json()
            checkout_url = data.get("url")
            print(f"SUCCESS: Created Session {data.get('id')}")
            return checkout_url
        else:
            print(f"POLAR REJECTION ({response.status_code}): {response.text}")
            return None

    except Exception as e:
        print(f"SYSTEM ERROR IN CHECKOUT: {str(e)}")
        return None
    finally:
        db.close()