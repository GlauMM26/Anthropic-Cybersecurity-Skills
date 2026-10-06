-- Dados iniciais de exemplo (idempotente: INSERT OR IGNORE pela coluna sku).
INSERT OR IGNORE INTO products (sku, name, description, price_cents, stock) VALUES
 ('TEC-001', 'Teclado mecânico',      'Switches táteis, layout ABNT2.',                 34990, 15),
 ('MOU-001', 'Mouse sem fio',         'Sensor óptico de 1600 DPI, 2.4 GHz.',             8990, 40),
 ('MON-001', 'Monitor 24" IPS',       'Full HD, 75 Hz, bordas finas.',                  89900,  8),
 ('HUB-001', 'Hub USB-C 7 em 1',      'HDMI, 3x USB-A, leitor SD, PD 100 W.',           19900, 25),
 ('KEY-001', 'Chave de segurança FIDO2', 'Autenticação forte sem senha (WebAuthn).',    24900, 30),
 ('CAB-001', 'Cabo de rede Cat6 2 m', 'Blindado, até 10 Gbps.',                          2490, 100);
