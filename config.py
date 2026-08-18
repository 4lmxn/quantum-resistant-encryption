# config.py

# Must be EXACTLY 32 bytes long for AES-256 (256 bits)
SESSION_KEY_A = b"sensor_link_quantum_safe_key_32B"  # 32 bytes
SESSION_KEY_B = b"actuator_link_quantum_safe_32B"  # 32 bytes

TEMP_THRESHOLD = 30.0