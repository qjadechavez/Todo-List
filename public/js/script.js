/** @format */

document.addEventListener("DOMContentLoaded", function () {
	const hamburger = document.querySelector(".hamburger");
	const navLinks = document.querySelector(".nav-links");

	hamburger.addEventListener("click", function () {
		navLinks.classList.toggle("active");
	});

	// Close menu when clicking outside
	document.addEventListener("click", function (e) {
		if (!hamburger.contains(e.target) && !navLinks.contains(e.target) && navLinks.classList.contains("active")) {
			navLinks.classList.remove("active");
		}
	});
});
