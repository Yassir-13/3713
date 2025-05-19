import { useEffect } from "react";
import axios from "axios";

function ProductList() {
  useEffect(() => {
    axios.get("http://localhost:8000/api/products")
      .then(response => {
        console.log("Réponse de Laravel 👇", response.data);
      })
      .catch(error => {
        console.error("Erreur de connexion à Laravel 😬", error);
      });
  }, []);
}

export default ProductList;
