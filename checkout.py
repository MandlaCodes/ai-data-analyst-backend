import os
import httpx
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    db = SessionLocal()
    try:
        user = get_user_by_email(db, customer_email)
        if not user:
            return None
            
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        # Ensure this is the ID for the PRICE, not just the product if possible
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        # FIX 1: Modern Polar API endpoint
        url = "https://api.polar.sh/api/v1/checkouts/custom/"
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        # FIX 2: Polar is strict about URLs. 
        # Sometimes it fails if there isn't a trailing slash BEFORE the query param.
        success_url = "https://metria.dev/dashboard/?payment=success"
        
        payload = {
            "product_id": product_id,
            "success_url": success_url,
            "customer_email": customer_email,
            "allow_discount_codes": True,
            # FIX 3: Required for redirects to work on custom domains
            "embed_origin": "https://metria.dev",
            "metadata": {
                "user_id": str(user.id),
                "email": customer_email
            }
        }

        with httpx.Client() as client:
            # We use post() and check for the redirect key in the response
            response = client.post(url, json=payload, headers=headers, timeout=15.0)
            
        if response.status_code in [200, 201]:
            res_data = response.json()
            # Double check: does the response echo our success_url?
            print(f"DEBUG: Polar confirmed success_url: {res_data.get('success_url')}")
            return res_data.get("url")
        else:
            print(f"POLAR API REJECTED REQUEST: {response.text}")
            return None

    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        return None
    finally:
        db.close()