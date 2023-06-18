let listElements = document.querySelectorAll(".link");

listElements.forEach((listElement) => {
  listElement.addEventListener("click", () => {
    if (listElement.classList.contains("active")) {
      listElement.classList.remove("active");
    } else {
      listElements.forEach((listE) => {
        listE.classList.remove("active");
      });
      listElement.classList.toggle("active");
    }
  });
});

let id = 1;
function movePara(e) {
  console.log("movePara");
  let name = this.name;
  Array.from(document.querySelectorAll(".p" + id)).forEach(function (it) {
    it.style.display = "none";
  });
  console.log("moveParaBLOCK");
  if (name === "next") {
    if (id == 3) {
      id = 1;
    } else {
      ++id;
    }
    Array.from(document.querySelectorAll(".p" + id)).forEach(function (it) {
      it.style.display = "block";
    });
  }
  if (name === "prev") {
    if (id == 1) {
      id = 3;
    } else {
      --id;
    }
    Array.from(document.querySelectorAll(".p" + id)).forEach(function (it) {
      it.style.display = "block";
    });
  }
}

window.onload = function () {
  var f = document.getElementById("moveBtns");
  f.next.addEventListener("click", movePara, false);
  f.prev.addEventListener("click", movePara, false);
};
