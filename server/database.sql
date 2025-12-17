CREATE TABLE IF NOT EXISTS sensor_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cipher_hex TEXT,
    nonce_hex VARCHAR(50),
    distance FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
