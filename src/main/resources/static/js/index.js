function loadFinished(){
    // Get the divs and the password input field
    const toggleElements = document.querySelectorAll('div.password-switch');
    const passwordInput = document.getElementById('password');

    if(passwordInput != null && toggleElements != null){
        // Add click event listener to toggle elements
        toggleElements.forEach(el => {
            el.addEventListener('click', () => {
                // Toggle the type of the password input field
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    toggleElements.forEach(el => {
                        // Remove Class
                        el.classList.add('text-red-400');
                    });
                } else {
                    passwordInput.type = 'password';
                    toggleElements.forEach(el => {
                        // Add Class
                        el.classList.remove('text-red-400');
                    });
                }

                // Set focus to the password input field
                passwordInput.focus();

                // Optional: Move the cursor to the end of the input field
                const length = passwordInput.value.length;
                passwordInput.setSelectionRange(length, length);
            });
        });
    }

        // Get the divs and the password input field
        const toggleConfirmElements = document.querySelectorAll('div.passwordConfirm-switch');
        const passwordConfirmInput = document.getElementById('passwordConfirm');

        if(passwordConfirmInput != null && toggleConfirmElements != null){
            // Add click event listener to toggle elements
            toggleConfirmElements.forEach(el => {
                el.addEventListener('click', () => {
                    // Toggle the type of the password input field
                    if (passwordConfirmInput.type === 'password') {
                        passwordConfirmInput.type = 'text';

                        toggleConfirmElements.forEach(el => {
                            // Remove Class
                            el.classList.add('text-red-400');
                        });

                    } else {
                        passwordConfirmInput.type = 'password';

                        toggleConfirmElements.forEach(el => {
                            // Add Class
                            el.classList.remove('text-red-400');
                        });
                    }

                    // Set focus to the password input field
                    passwordConfirmInput.focus();

                    // Optional: Move the cursor to the end of the input field
                    const length = passwordConfirmInput.value.length;
                    passwordConfirmInput.setSelectionRange(length, length);
                });
            });
        }

    const flashMessage = document.querySelectorAll('div.flash-message');
    const closeFlashMessage = document.querySelectorAll('div.close-flash-message');

    if (flashMessage != null && closeFlashMessage != null) {

        closeFlashMessage.forEach(el => {
            el.addEventListener('click', () => {
                flashMessage.forEach(el => {
                    el.style.display = 'none';
                });
            });
        });
    }
}