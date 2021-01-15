let r1 = /\d/;
let r2 = /[!@#$%^&*\-_]/;
let r3 = /([A-Z]|[ĄĘĆŃŁÓŻŹ])/;
let r4 = /([a-z]|[ąęćńłóźż])/;

const evaluatePassword = (password, strength) => {
    strength.textContent = r1.test(password) + r2.test(password) + r3.test(password) + r4.test(password);
};

window.onload = () => {
    let password = document.getElementById('password');
    let strength = document.getElementById('strength');

    password.addEventListener('input', (e) => {
        evaluatePassword(e.target.value, strength);
    });
}