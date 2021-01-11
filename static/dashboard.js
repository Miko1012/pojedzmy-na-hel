const revealPassword = async(url, id) => {
    console.log("wysyłam zapytanie i rozkodowuję hasło");
    await fetch(url)
        .then((r) => {
            if(r.status === 200) {
                return r.json();
            }
        })
        .then((a) => {
            let td = document.getElementById('passphrase-' + id);
            td.textContent = a.toString();
            let button = document.getElementById('decrypt-' + id);
            button.style.display = "none";
        });
};