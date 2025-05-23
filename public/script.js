function validateForm(event) {
    const inputs = document.querySelectorAll('input');
    for (const input of inputs) {
        if (!input.value.trim()) {
            alert('All fields are required!');
            event.preventDefault();
            return false;
        }
    }
}