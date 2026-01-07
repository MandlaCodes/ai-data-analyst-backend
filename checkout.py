import os
from polar_sdk import Polar
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    db = SessionLocal()
    try:
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"CHECKOUT ERROR: User {customer_email} not found.")
            return None
            
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID") 

        if not token or not product_id:
            print("CHECKOUT ERROR: Missing Environment Variables.")
            return None

        polar = Polar(access_token=token)
        
        # FINAL ATTEMPT: Wrapping in a single request object/dict
        # Some 0.x versions expect 'request' or 'data' or a positional object
        payload = {
            "product_id": product_id,
            "success_url": "https://metria.dev/dashboard?payment=success",
            "customer_email": customer_email,
            "metadata": {
                "user_id": str(user.id),
                "email": customer_email
            }
        }

        # Try passing it as the first positional argument which 
        # is common in these generated SDKs
        res = polar.checkouts.create(payload)
        
        if res and hasattr(res, 'url'):
            print(f"CHECKOUT SUCCESS: {res.url}")
            return res.url
        
        return None

    except Exception as e:
        print(f"SDK ERROR DETAIL: {str(e)}")
        # If the above fails, one last fallback: the 'request' keyword
        try:
            print("Trying fallback 'request' keyword...")
            res = polar.checkouts.create(request=payload)
            return res.url if res else None
        except Exception as e2:
            print(f"FALLBACK ERROR: {str(e2)}")
            return None
    finally:
        db.close()