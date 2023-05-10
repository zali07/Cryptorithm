const wrapper = document.querySelector(".wrapper");
const loginLink = document.querySelector(".login-link");
const signupLink = document.querySelector(".signup-link");
const btnLogin = document.querySelector(".btnLogin-popup");
const iconClose = document.querySelector(".icon-close");

loginLink.addEventListener("click", () => {
  wrapper.classList.remove("active");
});

signupLink.addEventListener("click", () => {
  wrapper.classList.add("active");
});

btnLogin.addEventListener("click", () => {
  wrapper.classList.add("active-popup");
});

iconClose.addEventListener("click", () => {
  wrapper.classList.remove("active-popup");
});
