const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'MD DB',
  password: 'J1002209528j',
  port: 5432,
});

pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error adquiriendo el cliente', err.stack);
  }
  console.log('Conexión a PostgreSQL exitosa');
  release();
});

module.exports = pool;
