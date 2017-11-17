function redirectTo(url) {
  window.location.href = url;
}

function displayResult(id, start, end, amount){
  var resultHtml = "Ride id: " + id + "<br>"
                  + "Amount: " + amount + "<br>"
                  + "Start: " + start + "<br>"
                  + "End: " + end + "<br>"

  $('div#info').html(resultHtml);
}
function meterToMile(meter) {
  return meter/1609.344;
}

function calculatePrice (mile) {
  var chargedMile = mile - 2;
  var price = chargedMile * 10;

  if (price < 15) {
    return 15;
  } else {
    return Math.round(price);
  }
}

function DisplayRoute(directionsService, start, end, id) {
  directionsService.route({
    origin: start,
    destination: end,
    travelMode: 'DRIVING'
  }, function(response, status) {
    if (status === 'OK') {
      console.log('Current POS');
      console.log(start);
      console.log('User addr');
      console.log(end);
      console.log(response.routes[0].legs[0].distance.value);
      var amount = calculatePrice(meterToMile(response.routes[0].legs[0].distance.value));
      console.log(amount);

      displayResult(id, start, end, amount);

    } else {
      window.alert('Directions request failed due to ' + status);
    }
  });
}

payment = {
  initGoogleMaps: function(ride){
    var directionsService = new google.maps.DirectionsService;
    console.log("payment.js is loaded");
    console.log(ride);
    DisplayRoute(directionsService, ride.start_location, ride.end_location, ride.ride_id);
  },
};
