import os
from polar_sdk import Polar
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    db = SessionLocal()
    try:
        # 1. Verify user exists in the NEW production DB
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"CHECKOUT ERROR: User {customer_email} not found in PostgreSQL.")
            return None
            
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        # 2. Safety check for Environment Variables
        if not token or not product_id:
            print("CHECKOUT ERROR: POLAR_ACCESS_TOKEN or POLAR_PRODUCT_ID is missing in Render Env.")
            return None

        # 3. Initialize Polar Client (NO 'with' statement - this was the crash)
        polar = Polar(access_token=token)
        
        # 4. Create the checkout session
        # Use 'custom' create for specific product IDs
        res = polar.checkouts.custom.create(
            product_id=product_id,
            success_url="https://metria.dev/dashboard?payment=success",
            customer_email=customer_email,
            metadata={
                "user_id": str(user.id),
                "email": customer_email
            }
        )
        
        print(f"CHECKOUT SUCCESS: Generated URL for {customer_email}")
        return res.url

    except Exception as e:
        # This will show the EXACT error from Polar in your Render Logs
        print(f"CRITICAL POLAR SDK ERROR: {str(e)}")
        return None
    finally:
        db.close()