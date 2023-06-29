function deleteData(dataId, lang) {
  fetch("/delete-data", {
    method: "POST",
    body: JSON.stringify({ dataId: dataId }),
  }).then((_res) => {
    console.log(lang);
    window.location.href = "/" + lang;
  });
}

function createInputElementNumber(inputName) {
  var container = document.getElementById("inputContainer");
  var element = document.createElement("input");
  element.type = "number";
  element.name = inputName;
  element.required = true;
  container.appendChild(element);
}

function createInputElementText(inputName) {
  var container = document.getElementById("inputContainer");
  var element = document.createElement("input");
  element.type = "text";
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
      createLabelElement("shift:");
      createInputElementNumber("CAESAR_EN_SHIFT");
      break;
    case "CAESAR_DE":
      createLabelElement("shift:");
      createInputElementNumber("CAESAR_DE_SHIFT");
      break;
    case "AFFINE_EN":
      createLabelElement("a:");
      createInputElementNumber("AFFINE_EN_A");
      createLabelElement("b:");
      createInputElementNumber("AFFINE_EN_B");
      break;
    case "AFFINE_DE":
      createLabelElement("a:");
      createInputElementNumber("AFFINE_DE_A");
      createLabelElement("b:");
      createInputElementNumber("AFFINE_DE_B");
      break;
    case "AES-128_CTR_EN":
      createLabelElement("password:");
      createInputElementText("AES-128-CTR_PASS");
      break;
    case "AES-128_CTR_DE":
      createLabelElement("key:");
      createInputElementText("AES-128-CTR_KEY");
      createLabelElement("nonce:");
      createInputElementText("AES-128-CTR_NONCE");
      break;
    case "AES-256_CTR_EN":
      createLabelElement("password:");
      createInputElementText("AES-256-CTR_PASS");
      break;
    case "AES-256_CTR_DE":
      createLabelElement("key:");
      createInputElementText("AES-256-CTR_KEY");
      createLabelElement("nonce:");
      createInputElementText("AES-256-CTR_NONCE");
      break;
    case "CHACHA20_DE":
      createLabelElement("key:");
      createInputElementText("CHACHA20_KEY");
      createLabelElement("nonce:");
      createInputElementText("CHACHA20_NONCE");
      break;
    case "BLOWFISH_DE":
      createLabelElement("key:");
      createInputElementText("BLOWFISH_KEY");
      break;
    default:
      break;
  }
}

$("#langSwitcher").on("change", function () {
  window.location = window.location.href.slice(0, -2) + $(this).val();
});

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
