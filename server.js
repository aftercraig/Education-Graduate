const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');
app.use(express.static('public'));

// Подключение к базе данных
let db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT, password TEXT)");
    db.run("CREATE TABLE courses (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, content TEXT, author_id INTEGER, rating REAL)");
    db.run("CREATE TABLE user_courses (user_id INTEGER, course_id INTEGER)");
});

// Секретный ключ для JWT
const secretKey = 'your_secret_key';

// Middleware для проверки авторизации
function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Регистрация
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [username, email, hashedPassword], function(err) {
        if (err) {
            return res.send('Ошибка регистрации');
        }
        res.redirect('/login');
    });
});

// Авторизация
app.post('/login', async (req, res) => {
    const { identifier, password } = req.body;
    let user = null;
    db.get("SELECT * FROM users WHERE username = ? OR email = ?", [identifier, identifier], (err, row) => {
        if (err || !row) {
            return res.send('Неверные данные');
        }
        user = row;
        bcrypt.compare(password, user.password, (err, result) => {
            if (err || !result) {
                return res.send('Неверные данные');
            }
            const token = jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true });
            res.redirect('/');
        });
    });
});

// Главная страница
app.get('/', authenticateToken, (req, res) => {
    db.all("SELECT * FROM courses", [], (err, rows) => {
        if (err) {
            return res.send('Ошибка получения курсов');
        }
        res.render('index', { courses: rows, user: req.user });
    });
});

// Персональный кабинет
app.get('/profile', authenticateToken, (req, res) => {
    db.all("SELECT c.* FROM courses AS c JOIN user_courses AS uc ON c.id = uc.course_id WHERE uc.user_id = ?", [req.user.id], (err, rows) => {
        if (err) {
            return res.send('Ошибка получения курсов');
        }
        res.render('profile', { courses: rows, user: req.user });
    });
});

// Конструктор курсов
app.get('/create-course', authenticateToken, (req, res) => {
    res.render('create-course', { user: req.user });
});

app.post('/create-course', authenticateToken, (req, res) => {
    const { title, description, content } = req.body;
    db.run("INSERT INTO courses (title, description, content, author_id) VALUES (?, ?, ?, ?)", [title, description, content, req.user.id], function(err) {
        if (err) {
            return res.send('Ошибка создания курса');
        }
        res.redirect('/');
    });
});

// Поиск и сортировка курсов
app.get('/search', authenticateToken, (req, res) => {
    const { query, sort } = req.query;
    let sql = "SELECT * FROM courses";
    const params = [];
    if (query) {
        sql += " WHERE title LIKE ?";
        params.push(`%${query}%`);
    }
    if (sort === 'rating') {
        sql += " ORDER BY rating DESC";
    }
    db.all(sql, params, (err, rows) => {
        if (err) {
            return res.send('Ошибка поиска курсов');
        }
        res.render('search', { courses: rows, user: req.user });
    });
});

// Логин
app.get('/login', (req, res) => {
    res.render('login');
});

// Регистрация
app.get('/register', (req, res) => {
    res.render('register');
});

// Выход
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

app.listen(3000, () => {
    console.log('Server started on http://localhost:3000');
});