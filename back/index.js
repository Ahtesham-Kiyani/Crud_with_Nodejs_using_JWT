const express = require("express");
const app = express();
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const util = require("util");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

app.use(bodyParser.json());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "shamiiixd@99",
  database: "crud",
});

const dbQuery = util.promisify(db.query).bind(db);

const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) {
    return res.status(401).json({ error: "Unauthorized - Token not provided" });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Forbidden - Invalid token" });
    }
    req.user = user;
    next();
  });
};

async function getuserfromdatabase(username) {
  try {
    const query = "SELECT * FROM users WHERE name=?";
    const results = await dbQuery(query, [username]);
    return results[0];
  } catch (error) {
    console.error("Error retrieving user from the database:", error);
    throw error;
  }
}

function generatetoken(payload) {
  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "1h",
  });
}

const saltrounds = 10;

app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    const existinguser = await getuserfromdatabase(username);
    if (existinguser) {
      return res.status(400).json({ error: "User already exists" });
    }
    const hasedpassword = await bcrypt.hash(password, saltrounds);
    const insertquery = "insert into users (name,password) values (?,?)";
    const insertvalues = [username, hasedpassword];
    await dbQuery(insertquery, insertvalues);
    return res
      .status(200)
      .json({ message: "User Succesfully created! Now you can login" });
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await getuserfromdatabase(username);

    if (user) {
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        const token = generatetoken({ userId: user.id, username: user.name });
        return res.status(200).json({ token });
      } else {
        return res.status(401).json({ message: "Invalid credentials" });
      }
    } else {
      return res.status(500).json({ message: "User not found" });
    }
  } catch (error) {
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/profile", authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const username = req.user.username;
  res.json({ userId, username });
});

app.post("/insert", authenticateToken, async (req, res) => {
  const { first_name, last_name, email, phone_number } = req.body;

  const insertQuery = `
    INSERT INTO employee (first_name, last_name, email, phone_number)
    VALUES (?, ?, ?, ?)
  `;

  const values = [first_name, last_name, email, phone_number];

  try {
    const results = await new Promise((resolve, reject) => {
      db.query(insertQuery, values, (err, results) => {
        if (err) {
          reject(err);
        } else {
          resolve(results);
        }
      });
    });

    console.log("New employee inserted");
    return res.status(200).json({ message: "Employee inserted successfully" });
  } catch (error) {
    console.error("Error executing insert query:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/employees", authenticateToken, async (req, res) => {
  const query = "SELECT * FROM employee";

  try {
    const results = await dbQuery(query);
    return res.status(200).json(results);
  } catch (error) {
    console.error("Error executing query:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.delete("/delete/:id", authenticateToken, async (req, res) => {
  const employeeId = req.params.id;

  const deleteQuery = "DELETE FROM employee WHERE id = ?";

  try {
    const results = await new Promise((resolve, reject) => {
      db.query(deleteQuery, [employeeId], (err, results) => {
        if (err) {
          reject(err);
        } else {
          resolve(results);
        }
      });
    });

    console.log("Employee deleted");
    return res.status(200).json({ message: "Employee deleted successfully" });
  } catch (error) {
    console.error("Error executing delete query:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/update/:id", authenticateToken, async (req, res) => {
  const employeeId = req.params.id;
  const { first_name, last_name, email, phone_number } = req.body;

  if (!first_name || !last_name || !email || !phone_number) {
    return res.status(500).json({ error: "All fields are required" });
  }

  const updateQuery = `
    UPDATE employee
    SET first_name = ?, last_name = ?, email = ?, phone_number = ?
    WHERE id = ?
  `;

  const values = [first_name, last_name, email, phone_number, employeeId];

  try {
    const results = await new Promise((resolve, reject) => {
      db.query(updateQuery, values, (err, results) => {
        if (err) {
          reject(err);
        } else {
          resolve(results);
        }
      });
    });

    console.log("Employee updated");
    return res.status(200).json({ message: "Employee updated successfully" });
  } catch (error) {
    console.error("Error executing update query:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
