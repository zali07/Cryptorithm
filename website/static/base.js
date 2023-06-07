function deleteNote(noteId) {
  fetch("/delete-note", {
    method: "POST",
    body: JSON.stringify({ noteId: noteId }),
  }).then((_res) => {
    window.location.href = "/";
  });
}

function createInputElement(inputName) {
  var container = document.getElementById("inputContainer");
  var element = document.createElement("input");
  element.type = "number";
  element.name = inputName;
  element.required = true;
  container.appendChild(element);
}

function createLabelElement(labelName) {
  var container = document.getElementById("inputContainer");
  var element = document.createElement("label");
  element.innerHTML = labelName;
  element.classList.add("algLabel");
  container.appendChild(element);
}

function addInputs() {
  var select = document.getElementById("enty");
  var option = select.options[select.selectedIndex].value;
  var container = document.getElementById("inputContainer");
  container.innerHTML = "";

  switch (option) {
    case "CAESAR_EN":
      createLabelElement("Shift:");
      createInputElement("CAESAR_EN_SHIFT");
      break;
    case "AFFINE_EN":
      createLabelElement("a:");
      createInputElement("AFFINE_EN_A");
      createLabelElement("b:");
      createInputElement("AFFINE_EN_B");
      break;
    case "CAESAR_DE":
      createLabelElement("Shift:");
      createInputElement("CAESAR_DE_SHIFT");
      break;
    case "AFFINE_DE":
      createLabelElement("a:");
      createInputElement("AFFINE_DE_A");
      createLabelElement("b:");
      createInputElement("AFFINE_DE_B");
      break;
    default:
      break;
  }
}

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
