driverfound = {
  initGoogleMaps: function(lat, lng){
    console.log("Driver found is loaded");
    console.log("Lat: " + lat);
    console.log("Lng: " + lng);
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
      driverPos = {
        lat: lat,
        lng: lng
      }
      var driverM = new google.maps.Marker({
        position: driverPos,
        title:"You are here!"
      });

      marker.setMap(map);
      driverM.setMap(map);
      map.setCenter(pos);
      map.setZoom(12);
    });
    directionsDisplay.setMap(map);
  },
};
