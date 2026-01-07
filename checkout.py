import os
import httpx
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    """
    Direct API Implementation - Bypasses the broken SDK.
    Guaranteed to work if your Token and Product ID are correct.
    """
    db = SessionLocal()
    try:
        # 1. Verify user
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"CHECKOUT ERROR: User {customer_email} not found.")
            return None
            
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        if not token or not product_id:
            print("CHECKOUT ERROR: Missing POLAR_ACCESS_TOKEN or POLAR_PRODUCT_ID in Render.")
            return None

        # 2. Call Polar API directly
        # API Docs: https://api.polar.sh/api/v1/checkouts/custom/
        url = "https://api.polar.sh/api/v1/checkouts/custom/"
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        payload = {
            "product_id": product_id,
            "success_url": "https://metria.dev/dashboard?payment=success",
            "customer_email": customer_email,
            "metadata": {
                "user_id": str(user.id),
                "email": customer_email
            }
        }

        print(f"DEBUG: Attempting direct API call for {customer_email}...")
        
        with httpx.Client() as client:
            response = client.post(url, json=payload, headers=headers, timeout=10.0)
            
        # 3. Handle Response
        if response.status_code == 201 or response.status_code == 200:
            data = response.json()
            checkout_url = data.get("url")
            print(f"CHECKOUT SUCCESS: {checkout_url}")
            return checkout_url
        else:
            print(f"API ERROR ({response.status_code}): {response.text}")
            return None

    except Exception as e:
        print(f"DIRECT API CRITICAL ERROR: {str(e)}")
        return None
    finally:
        db.close()