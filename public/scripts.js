document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.enroll').forEach(button => {
        button.addEventListener('click', () => {
            alert('Курс успешно пройден!');
        });
    });
});