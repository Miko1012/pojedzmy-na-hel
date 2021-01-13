const revealPassword = async(url, id) => {
    await fetch(url)
        .then((r) => {
            if(r.status === 200) {
                return r.json();
            }
        })
        .then((data) => {
            let td = document.getElementById('passphrase-' + id);
            td.textContent = data.toString();
            let button = document.getElementById('decrypt-' + id);
            button.style.display = "none";
            let button2 = document.getElementById('copy-' + id);
            button2.style.display = "initial";
        });
};
const copyPassword = async(id) => {
    let td = document.getElementById('passphrase-' + id);
    await navigator.clipboard.writeText(td.textContent);
    let button = document.getElementById('copy-' + id);
    button.textContent = "Skopiowano!";
    setTimeout(() => button.textContent = "Skopiuj", 1000);
}