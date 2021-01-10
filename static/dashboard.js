const revealPassword = async(url) => {
    console.log("wysyłam zapytanie i rozkodowuję hasło");
    console.log(url);
    const response = await fetch(url);
    console.log(response);
    if(response.status === 200) {
        console.log(response.json());
    }
};