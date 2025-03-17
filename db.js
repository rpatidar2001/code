const mysql = require("mysql2");

const connection = mysql.createConnection({
    host: "localhost", // Agar remote server hai to uska IP/URL
    user: "root", // Tumhara MySQL username
    password: "", // Tumhara MySQL password
    database: "my_database" // Jo database tumne create kiya
});

connection.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err);
        return;
    }
    console.log("Connected to MySQL database!");
});

module.exports = connection;
