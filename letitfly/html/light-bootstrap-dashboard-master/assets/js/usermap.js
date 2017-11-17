function meterToMile(meter) {
  return meter/1609.344;
}

function calculatePrice (mile) {
  var chargedMile = mile - 2;
  var price = chargedMile * 10;

  if (price < 15) {
    return 15;
  } else {
    return price;
  }
}

function mapAirportCode(code) {
  var AirportCode = {
    "SFO": "San Francisco International Airpot",
    "OAK": "Oakland International Airport",
    "SJC": "Norman Y. Mineta San Jose International Airport",
  };
  for (var key in AirportCode){
    if (key == code){
      return AirportCode[key];
    }
  }
};

function sendRideRequest(start, end) {
  var jsonData = {
    "start_location": start,
    "end_location": end
  };

  console.log(jsonData);

  $.ajax({
    method: "POST",
    url: "/request",
    data: JSON.stringify(jsonData),
    contentType: "application/json; charset=utf-8",
    dataType: "json",
  })
  /*
   * Excecuted when success
   */
    .done(function (data) {
      console.log("Json from API server " + data.message);
      window.location.href = "waiting";
    })
  /*
   * Excecuted when unsuccessful
   */
    .fail(function (jqXHR) {
      // Invoke error pop-up
      console.log(jqXHR.responseJSON);
    });
}

function calculateAndDisplayRoute(directionsService, directionsDisplay, currentPos) {
  directionsService.route({
    // origin: document.getElementById('start').value,
    origin: currentPos,
    destination: mapAirportCode(document.getElementById('end').value),
    travelMode: 'DRIVING'
  }, function(response, status) {
    if (status === 'OK') {
      console.log(response);
      directionsDisplay.setDirections(response);
      // document.getElementById("duration").value = response.routes.
      var resultText = "Duration: " + response.routes[0].legs[0].duration.text +
        "<br>Distance: " + response.routes[0].legs[0].distance.text +
        "<br>$ " + meterToMile(calculatePrice(response.routes[0].legs[0].distance.value));
      document.getElementById("duration").innerHTML = resultText;

      var reqButtonText = '<input id="request" type="button" value="Request a ride" />';
      document.getElementById("reqbutton").innerHTML = reqButtonText;

      var onClickHandler = function() {
        navigator.geolocation.getCurrentPosition(function(position) {
          var startPosLatLng = {
            lat: position.coords.latitude,
            lng: position.coords.longitude
          };
          var startPos;
          var geocoder = new google.maps.Geocoder;
          geocoder.geocode({'location': startPosLatLng}, function(results, status) {
            if (status === 'OK') {
              if (results[0]) {
                startPos = results[0].formatted_address;
                console.log('Request button clicked [Start Pos]: ' + startPos);
                var endPos = mapAirportCode(document.getElementById('end').value);
                console.log('Request button clicked [End Pos]: ' + endPos);
                sendRideRequest(startPos, endPos);
              } else {
                window.alert('No results found');
              }
            } else {
              window.alert('Geocoder failed due to: ' + status);
            }
          });
        });
      };
      document.getElementById('request').addEventListener('click', onClickHandler);
    } else {
      window.alert('Directions request failed due to ' + status);
    }
  });
}

usermap = {
  initGoogleMaps: function(){
    var directionsService = new google.maps.DirectionsService;
    var directionsDisplay = new google.maps.DirectionsRenderer;

    var map = new google.maps.Map(document.getElementById('map'), {
      zoom: 7,
      center: {lat: 37.33542741901094, lng: -121.88427904493496}
    });
    navigator.geolocation.getCurrentPosition(function(position) {
      var pos = {
        lat: position.coords.latitude,
        lng: position.coords.longitude
      };
      console.log(pos)
      var marker = new google.maps.Marker({
        position: pos,
        title:"You are here!"
      });

      // To add the marker to the map, call setMap();
      // marker.setMap(map);
      map.setCenter(pos);
      map.setZoom(12);
    });
    directionsDisplay.setMap(map);

    var onChangeHandler = function() {
      navigator.geolocation.getCurrentPosition(function(position) {
        var pos = {
          lat: position.coords.latitude,
          lng: position.coords.longitude
        };
        console.log('End changed [Current Pos]: ' + pos);
        calculateAndDisplayRoute(directionsService, directionsDisplay, pos);
      });
    };
    document.getElementById('end').addEventListener('change', onChangeHandler);

  },
}

