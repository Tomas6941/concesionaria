# 🚗 Concesionaria — Sistema de Gestión

Aplicación web desarrollada con Python (Flask) para una concesionaria de autos. Permite gestionar el inventario de vehículos y facilitar el contacto entre clientes e interesados en los vehículos disponibles. Permite la creación de cuentas, (utiliza verificación mediante gmail) y personalización de perfil (básico).


## 🛠️ Tecnologías utilizadas

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat&logo=css3&logoColor=white)

---

## ✨ Funcionalidades

- 🚘 Catálogo de vehículos disponibles
- 📬 Sistema de contacto / consultas de clientes
- ⚙️ Configuración personalizable desde el código

---

## 📁 Estructura del proyecto

```
concesionaria/
├── app.py              # Servidor Flask y rutas
├── templates/
│   └── *.html          # Plantillas HTML (Jinja2)
└── static/
    ├── css/            # Estilos
    └── js/             # Scripts
```

---

## ⚙️ Cómo ejecutar

1. Cloná el repositorio:
   ```bash
   git clone https://github.com/Tomas6941/concesionaria.git
   cd concesionaria
   ```
2. Creá un entorno virtual e instalá dependencias:
   ```bash
   python -m venv venv
   source venv/bin/activate   # En Windows: venv\Scripts\activate
   pip install flask
   ```
3. Configurá tus datos en `app.py` (líneas 19, 20, 21 y 24)

4. Ejecutá la aplicación:
   ```bash
   python app.py
   ```
5. Abrí tu navegador en `http://localhost:5000`

---

## 👨‍💻 Autor

**Tomás** — [GitHub](https://github.com/Tomas6941)
