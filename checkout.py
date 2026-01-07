import os
from polar_sdk import Polar
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    """
    Generates a Polar Checkout URL for the 'Hire Your AI Analyst' flow.
    Fixed for Polar SDK v1.x+ (using products list instead of product_id).
    """
    db = SessionLocal()
    try:
        # 1. Verify user exists in the production DB
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"CHECKOUT ERROR: User {customer_email} not found in DB.")
            return None
            
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        # 2. Safety check for Environment Variables
        if not token or not product_id:
            print("CHECKOUT ERROR: POLAR_ACCESS_TOKEN or POLAR_PRODUCT_ID missing in Render.")
            return None

        # 3. Initialize Polar Client
        # The 'with' statement is removed as it's not supported in current versions
        polar = Polar(access_token=token)
        
        # 4. Create the checkout session
        # CRITICAL FIX: The SDK now requires 'products=[product_id]' instead of 'product_id=product_id'
        res = polar.checkouts.custom.create(
            products=[product_id], 
            success_url="https://metria.dev/dashboard?payment=success",
            customer_email=customer_email,
            metadata={
                "user_id": str(user.id),
                "email": customer_email
            }
        )
        
        if hasattr(res, 'url') and res.url:
            print(f"CHECKOUT SUCCESS: URL generated for {customer_email}")
            return res.url
        
        print("CHECKOUT ERROR: Polar response did not contain a URL.")
        return None

    except Exception as e:
        # This will catch the 'unexpected keyword argument' error if the fix wasn't applied
        print(f"CRITICAL POLAR SDK ERROR: {str(e)}")
        return None
    finally:
        db.close()