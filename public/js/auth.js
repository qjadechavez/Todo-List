/** @format */

document.addEventListener("DOMContentLoaded", function () {
	// Toggle password visibility
	const toggleButtons = document.querySelectorAll(".toggle-password");
	toggleButtons.forEach((button) => {
		button.addEventListener("click", function () {
			const input = this.previousElementSibling;
			const type = input.getAttribute("type") === "password" ? "text" : "password";
			input.setAttribute("type", type);
			this.classList.toggle("fa-eye");
			this.classList.toggle("fa-eye-slash");
		});
	});

	// Password strength meter
	const passwordInput = document.getElementById("password");
	const passwordMeter = document.getElementById("password-meter");
	const passwordStrength = document.getElementById("password-strength");

	if (passwordInput && passwordMeter && passwordStrength) {
		passwordInput.addEventListener("input", function () {
			const value = passwordInput.value;
			let strength = 0;
			let status = "";

			if (value.length >= 8) strength += 20;
			if (value.match(/[a-z]+/)) strength += 20;
			if (value.match(/[A-Z]+/)) strength += 20;
			if (value.match(/[0-9]+/)) strength += 20;
			if (value.match(/[!@#$%^&*()]+/)) strength += 20;

			passwordMeter.style.width = strength + "%";

			if (strength <= 20) {
				passwordMeter.style.backgroundColor = "#FF4136";
				status = "Very Weak";
			} else if (strength <= 40) {
				passwordMeter.style.backgroundColor = "#FF851B";
				status = "Weak";
			} else if (strength <= 60) {
				passwordMeter.style.backgroundColor = "#FFDC00";
				status = "Medium";
			} else if (strength <= 80) {
				passwordMeter.style.backgroundColor = "#2ECC40";
				status = "Strong";
			} else {
				passwordMeter.style.backgroundColor = "#0074D9";
				status = "Very Strong";
			}

			passwordStrength.textContent = status;
		});
	}

	// Form validation
	const signupForm = document.querySelector('form[action="/signup"]');
	if (signupForm) {
		signupForm.addEventListener("submit", function (e) {
			const password = document.getElementById("password").value;
			const confirmPassword = document.getElementById("confirm-password").value;

			if (password !== confirmPassword) {
				e.preventDefault();
				alert("Passwords do not match!");
			}
		});
	}
});
