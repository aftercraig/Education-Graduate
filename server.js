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

// Подключение к базе данных
let db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT, password TEXT, avatar TEXT)");
    db.run("CREATE TABLE courses (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, content TEXT, author_id INTEGER, rating REAL)");
    db.run("CREATE TABLE user_courses (user_id INTEGER, course_id INTEGER)");
    db.run("CREATE TABLE course_ratings (user_id INTEGER, course_id INTEGER, rating INTEGER)");
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
    db.run("INSERT INTO users (username, email, password, avatar) VALUES (?, ?, ?, ?)", [username, email, hashedPassword, '/default-avatar.png'], function(err) {
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
    db.all("SELECT c.*, u.username AS author_name FROM courses AS c LEFT JOIN users AS u ON c.author_id = u.id", [], (err, rows) => {
        if (err) {
            return res.send('Ошибка получения курсов');
        }
        res.render('index', { courses: rows, user: req.user });
    });
});

// Персональный кабинет
app.get('/profile', authenticateToken, (req, res) => {
    db.get("SELECT * FROM users WHERE id = ?", [req.user.id], (err, user) => {
        if (err) {
            return res.send('Ошибка получения данных пользователя');
        }
        db.all("SELECT c.* FROM courses AS c JOIN user_courses AS uc ON c.id = uc.course_id WHERE uc.user_id = ?", [req.user.id], (err, completedCourses) => {
            if (err) {
                return res.send('Ошибка получения завершенных курсов');
            }
            db.all("SELECT c.* FROM courses AS c WHERE c.author_id = ?", [req.user.id], (err, createdCourses) => {
                if (err) {
                    return res.send('Ошибка получения созданных курсов');
                }
                res.render('profile', { user, completedCourses, createdCourses });
            });
        });
    });
});

// Конструктор курсов
app.get('/create-course', authenticateToken, (req, res) => {
    res.render('create-course', { user: req.user });
});

app.post('/create-course', authenticateToken, (req, res) => {
    const { title, description, content } = req.body;
    db.run("INSERT INTO courses (title, description, content, author_id, rating) VALUES (?, ?, ?, ?, 0)", [title, description, content, req.user.id], function(err) {
        if (err) {
            return res.send('Ошибка создания курса');
        }
        res.redirect('/');
    });
});

// Поиск и сортировка курсов
app.get('/search', authenticateToken, (req, res) => {
    const { query, sort } = req.query;
    let sql = "SELECT c.*, u.username AS author_name FROM courses AS c LEFT JOIN users AS u ON c.author_id = u.id";
    const params = [];
    if (query) {
        sql += " WHERE c.title LIKE ?";
        params.push(`%${query}%`);
    }
    if (sort === 'rating') {
        sql += " ORDER BY c.rating DESC";
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

// Персональная страница курса
app.get('/course/:id', authenticateToken, (req, res) => {
    const courseId = req.params.id;
    db.get("SELECT c.*, u.username AS author_name FROM courses AS c LEFT JOIN users AS u ON c.author_id = u.id WHERE c.id = ?", [courseId], (err, course) => {
        if (err || !course) {
            return res.send('Курс не найден');
        }
        db.get("SELECT AVG(rating) AS avg_rating FROM course_ratings WHERE course_id = ?", [courseId], (err, ratingRow) => {
            if (err) {
                return res.send('Ошибка получения рейтинга курса');
            }
            const avgRating = ratingRow.avg_rating ? parseFloat(ratingRow.avg_rating) : 0;
            course.rating = avgRating;
            res.render('course', { course, user: req.user });
        });
    });
});

// Оценка курса
app.post('/rate-course/:id', authenticateToken, (req, res) => {
    const courseId = req.params.id;
    const { rating } = req.body;
    db.run("INSERT INTO course_ratings (user_id, course_id, rating) VALUES (?, ?, ?)", [req.user.id, courseId, rating], function(err) {
        if (err) {
            return res.send('Ошибка оценки курса');
        }
        db.get("SELECT AVG(rating) AS avg_rating FROM course_ratings WHERE course_id = ?", [courseId], (err, ratingRow) => {
            if (err) {
                return res.send('Ошибка получения рейтинга курса');
            }
            const avgRating = ratingRow.avg_rating ? parseFloat(ratingRow.avg_rating) : 0;
            db.run("UPDATE courses SET rating = ? WHERE id = ?", [avgRating, courseId], function(err) {
                if (err) {
                    return res.send('Ошибка обновления рейтинга курса');
                }
                res.redirect(`/course/${courseId}`);
            });
        });
    });
});

// Изучение курса
app.post('/complete-course/:id', authenticateToken, (req, res) => {
    const courseId = req.params.id;
    db.run("INSERT INTO user_courses (user_id, course_id) VALUES (?, ?)", [req.user.id, courseId], function(err) {
        if (err) {
            return res.send('Ошибка завершения курса');
        }
        res.redirect(`/course/${courseId}`);
    });
});

app.listen(3000, () => {
    console.log('Server started on http://localhost:3000');
});