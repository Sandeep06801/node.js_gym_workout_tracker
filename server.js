const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const crypto = require('crypto');
const app = express();
const db = new sqlite3.Database('database.db');
const port = process.env.port || 3000;

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use(express.static('public'));

app.set('view engine', 'ejs');

const secretKey = crypto.randomBytes(32).toString('hex');
app.use(session({
    secret: secretKey,
    resave: false,
    saveUninitialized: true
}));

const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/');
  }
};

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.isAdmin) {
    return next();
  }

  return res.render('admin-access', { backUrl: '/admin/login' });

}

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  username TEXT UNIQUE,
  resetToken TEXT,
  password TEXT,
  salt TEXT,
  isAdmin INTEGER DEFAULT 0,
  date_created DATETIME DEFAULT CURRENT_TIMESTAMP

)`);

db.run(`CREATE TABLE IF NOT EXISTS workouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER,
  date TEXT,
  workoutType TEXT,
  workoutName TEXT,
  reps INTEGER,
  sets INTEGER,
  FOREIGN KEY (userId) REFERENCES users (id)
)`);

app.get('/', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    res.render('login');
  }
});

app.get('/admin/register', (req, res) => {
  db.get('SELECT COUNT(*) AS adminCount FROM users WHERE isAdmin = 1', (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    if (row.adminCount >= 1) {
      return res.send('Maximum admin accounts reached');
    }

    res.render('admin-register');
  });
});

app.post('/admin/register', (req, res) => {
  const { email, username, password } = req.body;

  const salt = crypto.randomBytes(16).toString('hex');
  const currentDate = new Date().toLocaleDateString('en-US', { timeZone: 'Asia/Kolkata' , dateStyle: 'medium' });

  const hashedPassword = crypto
    .createHash('sha1')
    .update(password + salt)
    .digest('hex');

  db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    if (row) {
      return res.status(400).send('Username already exists');
    }

    const query = 'INSERT INTO users (email, username, password, salt, isAdmin, date_created) VALUES (?, ?, ?, ?, 1, ?)';
    db.run(query, [email, username, hashedPassword, salt, currentDate], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }

      req.session.userId = this.lastID;

      res.render('admin-register-complete');
    });
  });
});

app.get('/admin/login', (req, res) => {
  res.render('admin-login');
});

app.post('/admin/login', (req, res) => {
  const { emailOrUsername, password } = req.body;
  db.get('SELECT id, username, password, salt FROM users WHERE (email = ? OR username = ?) AND isAdmin = 1', [emailOrUsername, emailOrUsername], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    if (!row) {
      return res.status(400).send('Invalid email or username');
    }

    const hashedPassword = crypto
      .createHash('sha1')
      .update(password + row.salt)
      .digest('hex');

    if (hashedPassword !== row.password) {
      return res.status(400).send('Invalid password');
    }

    req.session.userId = row.id;
    req.session.user = {
      id: row.id,
      username: row.username,
      isAdmin: true
    };

    res.redirect('/admin/dashboard');
  });
});

app.get('/admin/dashboard', isAdmin, (req, res) => {
  const userId = req.session.userId;

  db.all('SELECT id, email, username, isAdmin, date_created FROM users', (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    res.render('admin-dashboard', {users: rows});
  });
});

app.post('/admin/dashboard/search', isAdmin, (req, res) => {
  const { searchQuery } = req.body;

  db.all(`SELECT id, email, username, date_created FROM users WHERE id LIKE '%' || ? || '%' OR email LIKE '%' || ? || '%' OR username LIKE '%' || ? || '%'
    ORDER BY date_created DESC`, [searchQuery, searchQuery, searchQuery], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    res.render('admin-dashboard', { users: rows});
  });
});

app.post('/admin/user/delete/:id', isAdmin, (req, res) => {
  const userId = req.session.userId;
  const id = req.params.id;
  
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    if (row.isAdmin) {
      return res.render('admin-delete-error', { backUrl: '/admin/dashboard' });
    }

    db.run('DELETE FROM users WHERE id = ?', [id], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }

      if (this.changes === 0) {
        return res.status(404).send('User not found');
      }

      res.redirect('/admin/dashboard');
    });
  });
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    res.redirect('/admin/login');
  });
});

app.get('/login', (req, res) => {
    res.render('login');
});
  
app.post('/login', (req, res) => {
    const { emailOrUsername, password } = req.body;
      db.get('SELECT id, username, password, salt FROM users WHERE email = ? OR username = ?', [emailOrUsername, emailOrUsername], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
  
      if (!row) {
        return res.status(400).send('Invalid email or username');
      }
  
      const hashedPassword = crypto
        .createHash('sha1')
        .update(password + row.salt)
        .digest('hex');
  
      if (hashedPassword !== row.password) {
        return res.status(400).send('Invalid password');
      }
  
      req.session.userId = row.id;
  
      res.redirect('/dashboard');
    });
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    const { email, username, password } = req.body;
  
    const salt = crypto.randomBytes(16).toString('hex');
    const currentDate = new Date().toLocaleDateString('en-US', { timeZone: 'Asia/Kolkata' , dateStyle: 'medium'});

    const hashedPassword = crypto
      .createHash('sha1')
      .update(password + salt)
      .digest('hex');
  
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
  
      if (row) {
        return res.status(400).send('Username already exists');
      }
  
      const query = 'INSERT INTO users (email, username, password, salt, date_created) VALUES (?, ?, ?, ?, ?)';
      db.run(query, [email, username, hashedPassword, salt, currentDate], function (err) {
        if (err) {
          console.error(err);
          return res.status(500).send('Internal Server Error');
        }
  
        req.session.userId = this.lastID;
  
        res.render('register-complete');
      });
    });
});
  

app.get('/dashboard', isAuthenticated, (req, res) => {
  const userId = req.session.userId;

  db.all('SELECT * FROM workouts WHERE userId = ?', [userId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    res.render('dashboard', { workouts: rows });
  });
});

app.post('/dashboard/workouts', isAuthenticated, (req, res) => {
  const { date, workoutType, workoutName, reps, sets } = req.body;

  const userId = req.session.userId;

  db.run(
    'INSERT INTO workouts (userId, date, workoutType, workoutName, reps, sets) VALUES (?, ?, ?, ?, ?, ?)',
    [userId, date, workoutType, workoutName, reps, sets],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }

      res.redirect('/dashboard');
    }
  );
});

app.get('/dashboard/workouts/:id/edit', isAuthenticated, (req, res) => {
    const workoutId = req.params.id;
    const userId = req.session.userId;
  
    db.get('SELECT * FROM workouts WHERE id = ? AND userId = ?', [workoutId, userId], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
  
      if (!row) {
        return res.status(404).send('Workout not found');
      }
  
      res.render('edit-workout', { workout: row });
    });
});
  
app.post('/dashboard/workouts/:id', isAuthenticated, (req, res) => {
    const workoutId = req.params.id;
    const { date, workoutType, workoutName, reps, sets } = req.body;
  
    const query = 'UPDATE workouts SET date = ?, workoutType = ?, workoutName = ?, reps = ?, sets = ? WHERE id = ?';
    db.run(query, [date, workoutType, workoutName, reps, sets, workoutId], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error: ' + err.message);
      }
  
      res.redirect('/dashboard');
    });
});
  
app.delete('/dashboard/workouts/:id', isAuthenticated, (req, res) => {
    const workoutId = req.params.id;
    const userId = req.session.userId;
  
    db.run('DELETE FROM workouts WHERE id = ? AND userId = ?', [workoutId, userId], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
  
      if (this.changes === 0) {
        return res.status(404).send('Workout not found');
      }
  
      res.sendStatus(200); 
    });
});

app.use(function(req, res, next) {
  res.locals.user = req.user;
  next();
});

app.get('/profile', isAuthenticated, (req, res) => {
  const userId = req.session.userId;

  db.get('SELECT id, email, username FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    res.render('profile', { user: row, editMode: false });
  });
});

app.get('/profile/edit', isAuthenticated, (req, res) => {
  const userId = req.session.userId;

  db.get('SELECT id, email, username FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    res.render('edit-profile', { user: row, editMode: true });
  });
});

app.post('/profile/edit', isAuthenticated, (req, res) => {
  const { newEmail, newUsername } = req.body;
  const userId = req.session.userId;

  db.run('UPDATE users SET email = ?, username = ? WHERE id = ?', [newEmail, newUsername, userId], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    res.redirect('/profile');
  });
});

app.post('/profile', isAuthenticated, (req, res) => {
  const userId = req.session.userId;
  const { newUsername, newEmail } = req.body;

  db.get('SELECT id FROM users WHERE username = ? AND id != ?', [newUsername, userId], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    if (row) {
      return res.status(400).send('Username already exists. Please choose a different username.');
    }

    db.run('UPDATE users SET username = ?, email = ? WHERE id = ?', [newUsername, newEmail, userId], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }

      req.session.username = newUsername;

      res.redirect('/profile');
    });
  });
});

app.get('/profile/change-password', isAuthenticated, (req, res) => {
  res.render('change-password');
});

app.post('/profile/change-password', isAuthenticated, (req, res) => {

  if (req.body.cancel) {
    return res.redirect('/profile');
  }

  const currentPassword = req.body.currentPassword;
  const newPassword = req.body.newPassword;
  const confirmPassword = req.body.confirmPassword;

  const userId = req.session.userId;

  db.get('SELECT password, salt FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    const hashedCurrentPassword = crypto
      .createHash('sha1')
      .update(currentPassword + row.salt)
      .digest('hex');

    if (hashedCurrentPassword !== row.password) {
      return res.render('change-password', { error: 'Current password does not match' });
    }

    if (newPassword !== confirmPassword) {
      return res.render('change-password', { error: 'New password and confirm password do not match' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hashedNewPassword = crypto
      .createHash('sha1')
      .update(newPassword + salt)
      .digest('hex');

    db.run('UPDATE users SET password = ?, salt = ? WHERE id = ?', [hashedNewPassword, salt, userId], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
      req.session.passwordChanged = true;

      res.render('change-password', { passwordChanged: true });
    });
  });
});


app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { error: null });
});

app.post('/forgot-password', (req, res) => {
  const emailOrUsername = req.body.emailOrUsername;

  db.get('SELECT * FROM users WHERE email = ? OR username = ?', [emailOrUsername, emailOrUsername], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    if (!row) {
      return res.render('forgot-password', { error: 'Invalid email or username' });
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    const userId = row.id;

    db.run('UPDATE users SET resetToken = ? WHERE id = ?', [resetToken, userId], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }

      req.session.resetToken = resetToken;
      req.session.resetUserId = userId;

      res.redirect('/reset-password');
    });
  });
});

app.get('/reset-password', (req, res) => {
  const resetToken = req.session.resetToken;
  const resetUserId = req.session.resetUserId;

  if (!resetToken || !resetUserId) {
    return res.redirect('/forgot-password');
  }

  res.render('reset-password', { resetToken, resetUserId });
});

app.post('/reset-password', (req, res) => {
  const resetToken = req.session.resetToken;
  const resetUserId = req.session.resetUserId;

  if (!resetToken || !resetUserId) {
    return res.redirect('/forgot-password');
  }

  const { newPassword, confirmPassword } = req.body;

  if (newPassword !== confirmPassword) {
    return res.status(400).send('New password and confirm password do not match');
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hashedPassword = crypto
    .createHash('sha1')
    .update(newPassword + salt)
    .digest('hex');

  db.run('UPDATE users SET password = ?, salt = ?, resetToken = NULL WHERE id = ?', [hashedPassword, salt, resetUserId], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    delete req.session.resetToken;
    delete req.session.resetUserId;

    res.render('password-reset-success');
  });
});

app.get('/cancel', (req, res) => {
  res.render('cancel-page'); 
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.error('Logout error:', err);
        return res.status(500).send('Internal Server Error');
      }
      res.redirect('/');
    });
});
  
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
