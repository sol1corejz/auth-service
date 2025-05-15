INSERT INTO apps (app_id, name)
VALUES (gen_random_uuid(), 'coin-keeper')
    ON CONFLICT DO NOTHING;