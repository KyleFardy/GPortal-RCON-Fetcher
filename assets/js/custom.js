class GPRCON {
  constructor() {
    this.path = window.location.pathname;
  }

  async init() {
    $(() => {
      try {
        if (this.path === "/login") {
          this.initLogin();
        } else if (this.path === "/" || this.path === "/index") {
          this.initIndex();
        }
      } catch (err) {
        console.error("Failed To Init:", err);
      }
    });
  }

  initLogin() {
    $(document).on("keypress", async (e) => {
      if (e.which === 13) {
        await this.login();
      }
    });
    $("#login-button").on("click", async () => {
      await this.login();
    });
  }

  initIndex() {
    var table = $("#servers").DataTable({
      responsive: true,
      lengthMenu: [
        [8, 25, 50, -1],
        ["8 Servers", "25 Servers", "50 Servers", "Show All"],
      ],
      ajax: {
        url: "/includes/ajax/?action=getServers",
        type: "GET",
        data: function (d) {
          d.csrfToken = $('meta[name="csrf-token"]').attr("content");
        },
        dataSrc: function (json) {
          return json.data;
        },
        error: function (xhr, error, thrown) {
          console.error("Ajax error:", error);
          console.error("Thrown error:", thrown);
        },
      },
      columnDefs: [
        {
          className: "text-center",
          targets: "_all",
        },
      ],
      language: {
        lengthMenu: "Show _MENU_ Per Page",
        zeroRecords: "No Servers Found",
        info: "Showing _START_ To _END_ Of _TOTAL_ Servers",
        infoEmpty: "Showing No Servers",
        infoFiltered: "(Filtered From _MAX_ Total Servers)",
        loadingRecords:
          '<center><div class="spinner-border text-primary" role="status"> <span class="visually-hidden">Loading...</span></div></center>',
        search: "Search",
        paginate: {
          first: "First",
          last: "Last",
          next: "Next",
          previous: "Previous",
        },
      },
      columns: [
        { data: "hostname" },
        { data: "rconIpAddress" },
        { data: "rconPort" },
        { data: "rconPassword" },
      ],
    });
  }

  async login() {
    const loginButton = $("#login-button");
    const originalText = loginButton.text();
    loginButton.text("Logging In...").prop("disabled", true);

    const email = $("#email").val();
    const password = $("#password").val();

    if (!email || !password) {
      loginButton.text("Login").prop("disabled", false);
      this.alert(
        "Missing Fields",
        "error",
        "Please Enter Both Email And Password"
      );
      return;
    }

    $.ajax({
      url: "/includes/ajax/?action=login",
      type: "POST",
      data: {
        email,
        password,
        csrfToken: $('meta[name="csrf-token"]').attr("content"),
      },
      success: (response) => {
        try {
          const loginResponse = JSON.parse(response);
          this.alert(
            loginResponse.title,
            loginResponse.type,
            loginResponse.message
          );
          if (loginResponse.type === "success") {
            loginButton.text("Logged In").prop("disabled", true);
            setTimeout(() => {
              window.location.href = "/";
            }, 3000);
          }
        } catch (e) {
          loginButton.text("Login").prop("disabled", false);
          console.error("Failed To Parse Response:", e);
          this.alert("An Error Occurred", "Error", "Invalid Server Response");
        }
      },
      error: (xhr, status, error) => {
        loginButton.text("Login").prop("disabled", false);
        console.error("Error In Login:", error);
        this.alert("An Error Occurred", "Error", error);
      },
      complete: () => {
        loginButton.text(originalText).prop("disabled", false);
      },
    });
  }

  async alert(title, icon, html) {
    await Swal.fire({
      title,
      icon,
      html,
      confirmButtonText: "CONTINUE",
      buttonsStyling: false,
      customClass: {
        confirmButton: "btn btn-primary fw-bold",
        cancelButton: "btn btn-danger fw-bold",
        input: "form-control",
      },
    });
  }
}

window.addEventListener("load", () => {
  const rconFetcher = new GPRCON();
  rconFetcher.init();
});
