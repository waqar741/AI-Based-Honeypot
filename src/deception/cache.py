from src.database import get_connection

def get_cached_response(signature):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT fake_response FROM fake_responses WHERE attack_signature=?",
        (signature,)
    )
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def store_fake_response(signature, attack_type, response):
    conn = get_connection()
    cur = conn.cursor()
    
    # Using INSERT OR IGNORE to handle race conditions gracefully
    cur.execute(
        "INSERT OR IGNORE INTO fake_responses (attack_signature, attack_type, fake_response) VALUES (?, ?, ?)",
        (signature, attack_type, response)
    )
    conn.commit()
    conn.close()
