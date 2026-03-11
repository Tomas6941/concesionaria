CREATE DATABASE IF NOT EXISTS concesionaria_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE concesionaria_db;

CREATE TABLE IF NOT EXISTS autos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    marca VARCHAR(50) NOT NULL,
    modelo VARCHAR(100) NOT NULL,
    anio INT NOT NULL,
    precio DECIMAL(12,2) NOT NULL,
    km INT DEFAULT 0,
    tipo ENUM('sedan','suv','pickup','hatchback','coupe','van','convertible') DEFAULT 'sedan',
    transmision ENUM('manual','automatica') DEFAULT 'manual',
    combustible ENUM('nafta','diesel','hibrido','electrico') DEFAULT 'nafta',
    color VARCHAR(50),
    descripcion TEXT,
    imagen_url VARCHAR(500),
    disponible TINYINT(1) DEFAULT 1,
    destacado TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS test_drives (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL,
    telefono VARCHAR(30),
    auto_id INT,
    fecha DATE,
    mensaje TEXT,
    estado ENUM('pendiente','confirmado','cancelado') DEFAULT 'pendiente',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (auto_id) REFERENCES autos(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS contactos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL,
    telefono VARCHAR(30),
    asunto VARCHAR(200),
    mensaje TEXT NOT NULL,
    leido TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO autos (marca, modelo, anio, precio, km, tipo, transmision, combustible, color, descripcion, imagen_url, disponible, destacado) VALUES
('Toyota', 'Hilux 4x4 SRX', 2023, 38500000, 15000, 'pickup', 'automatica', 'diesel', 'Blanco', 'La pick-up más vendida de Argentina. Motor turbo diesel de 204 CV, tracción 4x4, caja automática de 6 velocidades. Equipamiento de lujo con pantalla táctil, cámara de reversa y control de crucero adaptativo.', 'https://images.unsplash.com/photo-1549317661-bd32c8ce0db2?w=800', 1, 1),
('Ford', 'Mustang GT 5.0', 2022, 52000000, 8000, 'coupe', 'manual', 'nafta', 'Rojo', 'Ícono americano con motor V8 de 450 CV. Performance pura con diferencial trasero de deslizamiento limitado electrónico, suspensión MagneRide y modo de conducción Track.', 'https://images.unsplash.com/photo-1544636331-e26879cd4d9b?w=800', 1, 1),
('BMW', 'X5 xDrive40i', 2023, 89000000, 5000, 'suv', 'automatica', 'nafta', 'Negro', 'El SUV premium por excelencia. Motor de 340 CV, tracción integral inteligente, suspensión neumática adaptativa y sistema de infoentretenimiento iDrive 8.', 'https://images.unsplash.com/photo-1555215695-3004980ad54e?w=800', 1, 1),
('Volkswagen', 'Golf GTI', 2023, 29000000, 0, 'hatchback', 'manual', 'nafta', 'Gris', 'El hot hatch de referencia. Motor turbo 2.0 TSI de 245 CV, diferencial de deslizamiento limitado electrónico VAQ y modo de conducción Sport.', 'https://images.unsplash.com/photo-1552519507-da3b142c6e3d?w=800', 1, 1),
('Toyota', 'RAV4 Hybrid', 2023, 45000000, 12000, 'suv', 'automatica', 'hibrido', 'Plata', 'SUV mediano con sistema híbrido de 218 CV combinados. Tracción AWD-i, bajos consumos de combustible y acceso sin llave.', 'https://images.unsplash.com/photo-1568844293986-ca9c5c1bc2e8?w=800', 1, 1),
('Mercedes-Benz', 'C 300 AMG Line', 2022, 75000000, 18000, 'sedan', 'automatica', 'nafta', 'Blanco', 'Sedán de lujo con motor de 258 CV, suspensión adaptativa AIRMATIC y paquete AMG Line exterior.', 'https://images.unsplash.com/photo-1618843479313-40f8afb4b4d8?w=800', 1, 1),
('Chevrolet', 'S10 High Country', 2023, 35000000, 20000, 'pickup', 'automatica', 'diesel', 'Gris', 'Pick-up full equipada con motor turbo diesel de 200 CV, caja automática de 6 velocidades y multitud de asistentes de conducción.', 'https://images.unsplash.com/photo-1503376780353-7e6692767b70?w=800', 1, 0),
('Honda', 'Civic Si', 2023, 27000000, 3000, 'sedan', 'manual', 'nafta', 'Azul', 'Sedán deportivo con motor turbo de 200 CV y caja manual de 6 velocidades. El placer de conducir en su máxima expresión.', 'https://images.unsplash.com/photo-1605559424843-9073c6223bd4?w=800', 1, 0);
