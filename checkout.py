import os
import httpx
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    """
    Direct API Implementation - Bypasses SDK.
    Handles the creation of a Polar checkout session and sets the 
    redirect path back to the dashboard with a success trigger.
    """
    db = SessionLocal()
    try:
        # 1. Verify the user exists in our database first
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"CHECKOUT ERROR: User {customer_email} not found.")
            return None
            
        # Get credentials from environment variables
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        if not token or not product_id:
            print("CHECKOUT ERROR: Missing POLAR_ACCESS_TOKEN or POLAR_PRODUCT_ID.")
            return None

        # 2. Polar API Endpoint for Custom Checkouts
        url = "https://api.polar.sh/api/v1/checkouts/custom/"
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # 3. Define the Payload
        # The success_url here is what triggers your "Preparing Metria" screen
        payload = {
            "product_id": product_id,
            "success_url": "https://metria.dev/dashboard?payment=success",
            "customer_email": customer_email,
            "metadata": {
                "user_id": str(user.id),
                "email": customer_email
            }
        }

        print(f"DEBUG: Generating Polar checkout link for {customer_email}...")
        
        # 4. Execute the Request
        with httpx.Client() as client:
            response = client.post(
                url, 
                json=payload, 
                headers=headers, 
                timeout=15.0
            )
            
        # 5. Process Response
        if response.status_code in [200, 201]:
            data = response.json()
            checkout_url = data.get("url")
            print(f"CHECKOUT CREATED: {checkout_url}")
            return checkout_url
        else:
            print(f"POLAR API ERROR ({response.status_code}): {response.text}")
            return None

    except Exception as e:
        print(f"CHECKOUT CRITICAL SYSTEM ERROR: {str(e)}")
        return None
    finally:
        # Always close the database connection
        db.close()