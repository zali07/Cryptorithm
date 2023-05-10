function deleteNote(noteId) {
  fetch("/delete-note", {
    method: "POST",
    body: JSON.stringify({ noteId: noteId }),
  }).then((_res) => {
    window.location.href = "/";
  });
}

function addInputs() {
  var select = document.getElementById("enty");
  var option = select.options[select.selectedIndex].value;
  var container = document.getElementById("inputContainer");
  container.innerHTML = "";

  switch (option) {
    case "CAESAR_EN":
      var CAESAR_EN_SHIFT = document.createElement("input");
      CAESAR_EN_SHIFT.type = "number";
      CAESAR_EN_SHIFT.name = "CAESAR_EN_SHIFT";
      container.appendChild(CAESAR_EN_SHIFT);
      break;
    case "AFFINE_EN":
      var AFFINE_EN_A = document.createElement("input");
      AFFINE_EN_A.type = "number";
      AFFINE_EN_A.name = "AFFINE_EN_A";
      container.appendChild(AFFINE_EN_A);
      var AFFINE_EN_B = document.createElement("input");
      AFFINE_EN_B.type = "number";
      AFFINE_EN_B.name = "AFFINE_EN_B";
      container.appendChild(AFFINE_EN_B);
      break;
    case "CAESAR_DE":
      var CAESAR_DE_SHIFT = document.createElement("input");
      CAESAR_DE_SHIFT.type = "number";
      CAESAR_DE_SHIFT.name = "CAESAR_DE_SHIFT";
      container.appendChild(CAESAR_DE_SHIFT);
      break;
    case "AFFINE_DE":
      var AFFINE_DE_A = document.createElement("input");
      AFFINE_DE_A.type = "number";
      AFFINE_DE_A.name = "AFFINE_DE_A";
      container.appendChild(AFFINE_DE_A);
      var AFFINE_DE_B = document.createElement("input");
      AFFINE_DE_B.type = "number";
      AFFINE_DE_B.name = "AFFINE_DE_B";
      container.appendChild(AFFINE_DE_B);
      break;
    default:
      break;
  }
}
