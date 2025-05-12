INSERT INTO apps (id, name)
VALUES (1, 'coin-keeper')
    ON CONFLICT DO NOTHING;