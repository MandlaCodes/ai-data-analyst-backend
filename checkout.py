import os
from polar_sdk import Polar
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    """
    Generates a Polar Checkout URL.
    Compatible with Polar SDK v0.28.1 (Flat Argument Syntax).
    """
    db = SessionLocal()
    try:
        # 1. Verify the user exists in your PostgreSQL DB
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"CHECKOUT ERROR: User {customer_email} not found in database.")
            return None
            
        # 2. Retrieve credentials from Render Environment Variables
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        if not token or not product_id:
            print("CHECKOUT ERROR: Missing POLAR_ACCESS_TOKEN or POLAR_PRODUCT_ID in Render.")
            return None

        # 3. Initialize the Polar Client
        polar = Polar(access_token=token)
        
        # 4. Create the checkout session
        # NOTE: Version 0.28.1 uses 'product_id' as a direct keyword argument.
        res = polar.checkouts.custom.create(
            product_id=product_id,
            success_url="https://metria.dev/dashboard?payment=success",
            customer_email=customer_email,
            metadata={
                "user_id": str(user.id),
                "email": customer_email
            }
        )
        
        # 5. Extract and return the URL
        if res and hasattr(res, 'url'):
            print(f"CHECKOUT SUCCESS: Generated URL for {customer_email}")
            return res.url
        
        print("CHECKOUT ERROR: Polar API response did not contain a valid URL.")
        return None

    except Exception as e:
        # This logs the exact reason if Polar rejects the request (e.g., invalid Token)
        print(f"CRITICAL POLAR SDK ERROR: {str(e)}")
        return None
    finally:
        db.close()