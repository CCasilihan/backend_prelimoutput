// userRoutes.js
const express = require('express');
const db = require('./db');
const { authenticateUser } = require('./authMiddleware');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); 



const { secretKey } = require('./secret');

const router = express.Router();

   
// Register endpoint


router.post('/register', async (req, res) => {
  const { userId, name, password, username } = req.body; // Change email to username here

  if (!name || !password || !username) { // Change email to username here
    return res.status(400).json({ error: 'name, password, and username are required.' }); // Change email to username here
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = 'INSERT INTO Users (userId, name, password, username) VALUES (?, ?, ?, ?)'; // Change email to username here
  
    db.query(query, [userId, name, hashedPassword, username], (err, result) => { // Change email to username here
      if (err) {
        console.error('Error executing INSERT query:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
  
      return res.json({ message: 'User registered successfully', id: result.insertId });
    });
  } catch (error) {
    console.error('Error hashing password:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});



// Login endpoint
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body; // Changed email to username here

    const getUserQuery = 'SELECT * FROM users WHERE username = ?'; // Changed to select by username
    const [rows] = await db.promise().execute(getUserQuery, [username]); // Changed email to username here

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' }); // Changed email to username here
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password' }); // Changed email to username here
    }

    const token = jwt.sign({ userId: user.id, username: user.username }, secretKey, { expiresIn: '1h' }); // Changed email to username here

    res.status(200).json({ token });
    
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


router.get('/users', (req, res) => {
  try {
    // Fetch users from the database
    db.query('SELECT userId, name, username FROM Users', (err, result) => { // Changed email to username here
      if (err) {
        console.error('Error fetching users:', err);
        return res.status(500).json({ message: 'Internal Server Error' });
      } else {
        return res.status(200).json(result);
      }
    });
  } catch (error) {
    console.error('Error loading users:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


// Update user details
router.put('/update/:userID', authenticateUser, (req, res) => {
  const { userID } = req.params;
  const { name, username } = req.body; // Changed email to username here

  if (!name || !username) { // Changed email to username here
    return res.status(400).json({ error: 'name and username are required.' }); // Changed email to username here
  } 

  const query = 'UPDATE Users SET name = ?, username = ? WHERE userID = ?'; // Changed email to username here

  db.query(query, [name, username, userID], (err, result) => { // Changed email to username here
    if (err) {
      console.error('Error executing UPDATE query:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json({ message: 'User details updated successfully' });
  });
});


router.delete('/delete/:userId', authenticateUser, async (req, res) => {
  const { userId } = req.params;

  if (!userId) {
    return res.status(400).json({ error: 'userId is required.' });
  }

  try {
    // Check if the user exists before attempting to delete
    const checkUserQuery = 'SELECT * FROM Users WHERE userId = ?';
    const [userRows] = await db.promise().query(checkUserQuery, [userId]);

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // If the user exists, proceed with the deletion
    const deleteQuery = 'DELETE FROM Users WHERE userId = ?';
    await db.promise().query(deleteQuery, [userId]);

    return res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error executing DELETE query:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ... (rest of the code)

module.exports = router;

// Logout endpoint
router.post('/logout', authenticateUser, (req, res) => {
  // Perform logout logic here
  // You might want to invalidate the token or clear the session
  return res.json({ message: 'Logout successful' });
});

module.exports = router;
