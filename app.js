const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');

const app = express();
const port = 3000;

mongoose.connect('mongodb://localhost/login-auth', { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.once('open', () => {
  console.log('Connected to MongoDB');
});

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'your-secret-key', resave: true, saveUninitialized: true }));

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to check if the user is logged in
const requireLogin = (req, res, next) => {
  if (req.session && req.session.userId) {
    return next();
  } else {
    res.redirect('/login');
  }
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword });
  newUser.save((err) => {
    if (err) {
      console.error(err);
      res.redirect('/');
    } else {
      res.redirect('/login');
    }
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  User.findOne({ username }, async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password))) {
      res.redirect('/');
    } else {
      req.session.userId = user._id;
      res.redirect('/secured');
    }
  });
});

app.get('/secured', requireLogin, (req, res) => {
  res.send('This is a secured page!');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
