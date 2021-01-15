const revealPassword = async (url, id) => {
    await fetch(url)
        .then((r) => {
            if (r.status === 200) {
                return r.json();
            }
        })
        .then((data) => {
            if (data.toString() !== "") {
                let td = document.getElementById('passphrase-' + id);
                td.textContent = data.toString();
                let button = document.getElementById('decrypt-' + id);
                button.style.display = "none";
                let button2 = document.getElementById('copy-' + id);
                button2.style.display = "initial";
            } else {
                let td = document.getElementById('passphrase-' + id);
                td.textContent = "błędne hasło odszyfrowujące dla danego hasła";
            }
        });
};
const copyPassword = async (id) => {
    let td = document.getElementById('passphrase-' + id);
    await navigator.clipboard.writeText(td.textContent);
    let button = document.getElementById('copy-' + id);
    button.textContent = "Skopiowano!";
    setTimeout(() => button.textContent = "Skopiuj", 1000);
}

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