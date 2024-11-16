const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const path = require('path');

const app = express();
const port = 3000;
const JWT_SECRET = 'G7123';
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin';

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
    res.send('¡Servidor en funcionamiento!');
});

app.get('/tienda', (req, res) => {
    res.sendFile(path.join(__dirname, 'Tienda.html'));
});

// Middleware para autenticar el token en las rutas protegidas
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];

    if (!token) return res.sendStatus(401); // Si no hay token, no está autorizado

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Si el token no es válido o ha expirado
        req.user = user;
        next();
    });
}

// Middleware para verificar si el usuario es administrador
function authenticateAdmin(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err || user.role !== 'admin') return res.sendStatus(403);
        next();
    });
}

// Ruta para servir la página de administración
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Ruta para iniciar sesión como administrador
app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;

    if (username === ADMIN_USER && password === ADMIN_PASS) {
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ message: 'Inicio de sesión exitoso', token });
    }

    res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
});

// Ruta protegida para el panel de administración
app.get('/admin-panel', authenticateAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await pool.query('SELECT * FROM "Usuarios" WHERE correo_electronico = $1 AND contraseña = $2', [email, password]);

        if (user.rows.length > 0) {
            const token = jwt.sign({ email: user.rows[0].correo_electronico }, JWT_SECRET, { expiresIn: '1h' });
            return res.json({ message: 'Inicio de sesión exitoso', token });
        } else {
            return res.status(401).send('Credenciales incorrectas');
        }
    } catch (err) {
        console.error('Error al iniciar sesión:', err);
        res.status(500).send('Error al iniciar sesión: ' + err.message);
    }
});

app.get('/products', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM "productos"');
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener productos:', err);
        res.status(500).send('Error al obtener productos: ' + err.message);
    }
});

app.post('/products', authenticateToken, async (req, res) => {
    const { nombre, marca, precio, drogueria, cantidad_disponible, categoria } = req.body;

    try {
        await pool.query(
            'INSERT INTO "productos" (nombre, marca, precio, drogueria, cantidad_disponible, categoria) VALUES ($1, $2, $3, $4, $5, $6)',
            [nombre, marca, precio, drogueria, cantidad_disponible, categoria]
        );
        res.status(201).json({ message: 'Producto agregado exitosamente' });
    } catch (err) {
        console.error('Error al agregar producto:', err);
        res.status(500).json({ message: 'Error al agregar el producto: ' + err.message });
    }
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'Register.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'Login.html'));
});

app.post('/register', async (req, res) => {
    const { username, password, email, phone, address } = req.body;

    try {
        const userExists = await pool.query(
            'SELECT nombre_usuario, telefono FROM "Usuarios" WHERE nombre_usuario = $1 OR telefono = $2',
            [username, phone]
        );

        if (userExists.rows.length > 0) {
            const existingUser = userExists.rows[0];
            if (existingUser.nombre_usuario === username) {
                return res.status(409).json({ field: 'username', message: 'Este nombre de usuario ya está en uso.' });
            } else if (existingUser.telefono === phone) {
                return res.status(409).json({ field: 'phone', message: 'Este número de teléfono ya está registrado.' });
            }
        }

        await pool.query(
            'INSERT INTO "Usuarios" (nombre_usuario, contraseña, correo_electronico, telefono, direccion_envio) VALUES ($1, $2, $3, $4, $5)',
            [username, password, email, phone, address]
        );

        res.status(201).json({ message: 'Usuario creado exitosamente' });
    } catch (err) {
        console.error('Error al registrar usuario:', err);
        res.status(500).json({ message: 'Error al registrar el usuario: ' + err.message });
    }
});

app.get('/user', authenticateToken, async (req, res) => {
    try {
        const user = await pool.query('SELECT * FROM "Usuarios" WHERE correo_electronico = $1', [req.user.email]);
        if (user.rows.length === 0) return res.status(404).json({ message: 'Usuario no encontrado' });

        const { nombre_usuario, telefono, direccion_envio } = user.rows[0];
        res.json({
            username: nombre_usuario,
            email: req.user.email,
            phone: telefono,
            address: direccion_envio
        });
    } catch (err) {
        res.status(500).json({ message: 'Error al obtener los datos del usuario: ' + err.message });
    }
});

app.post('/verify-password', authenticateToken, async (req, res) => {
    const { password } = req.body;

    try {
        const user = await pool.query('SELECT * FROM "Usuarios" WHERE correo_electronico = $1 AND contraseña = $2', [req.user.email, password]);
        if (user.rows.length === 0) return res.status(401).json({ success: false });

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Error al verificar la contraseña: ' + err.message });
    }
});

app.put('/update-profile', authenticateToken, async (req, res) => {
    const { username, password, phone, address } = req.body;

    try {
        await pool.query(
            'UPDATE "Usuarios" SET nombre_usuario = $1, contraseña = $2, telefono = $3, direccion_envio = $4 WHERE correo_electronico = $5',
            [username, password, phone, address, req.user.email]
        );
        res.json({ message: 'Perfil actualizado exitosamente' });
    } catch (err) {
        res.status(500).json({ message: 'Error al actualizar el perfil: ' + err.message });
    }
});

// Ruta para eliminar cuenta
app.delete('/delete-account', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM "Usuarios" WHERE correo_electronico = $1', [req.user.email]);
        res.json({ message: 'Cuenta eliminada exitosamente' });
    } catch (err) {
        res.status(500).json({ message: 'Error al eliminar la cuenta: ' + err.message });
    }
});

// Nueva ruta para la página de pago
app.get('/pago', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'Pago.html'));
});

// Ruta para verificar token
app.get('/verify-token', authenticateToken, (req, res) => {
    res.status(200).json({ message: 'Token válido' });
});

// Ruta para obtener los productos del carrito (protegida)
app.get('/cart', authenticateToken, (req, res) => {
    const cart = JSON.parse(localStorage.getItem('selectedProducts') || '[]');
    // Aquí puedes devolver el carrito solo para el usuario autenticado
    res.json(cart);
});

app.listen(port, () => {
    console.log(`Servidor en ejecución en http://localhost:${port}`);
});
