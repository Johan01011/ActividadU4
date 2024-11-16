// Array para almacenar los productos añadidos al carrito
let cart = [];

// Función para verificar si el usuario está autenticado
document.addEventListener('DOMContentLoaded', async () => {
    const token = localStorage.getItem('token'); // Obtener el token del almacenamiento local

    if (!token) {
        alert('Debes iniciar sesión para acceder a la tienda.');
        window.location.href = 'login.html'; // Redirige al inicio de sesión si no hay token
        return;
    }

    // Verificar si el token es válido
    const isValidToken = await verifyToken(token);
    if (!isValidToken) {
        alert('Tu sesión ha expirado o no eres un usuario válido.');
        window.location.href = 'login.html'; // Redirige al inicio de sesión si el token no es válido
        return;
    }

    // Verificar si hay productos guardados en localStorage bajo 'selectedProducts'
    const savedProducts = JSON.parse(localStorage.getItem('selectedProducts'));
    if (savedProducts) {
        cart = savedProducts; // Restaurar el carrito con los productos guardados
        updateCartCount(); // Actualizar el contador del carrito
        renderCart(); // Renderizar el carrito
    }

    // Cargar productos solo si hay un token válido
    await loadProducts();
});

// Función para verificar el token
async function verifyToken(token) {
    try {
        const response = await fetch('/verify-token', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`, // Agregar el token en el encabezado
            },
        });

        if (response.ok) {
            return true;
        } else {
            return false;
        }
    } catch (error) {
        console.error('Error al verificar el token:', error);
        return false;
    }
}

// Función para cargar productos desde la base de datos
async function loadProducts() {
    const token = localStorage.getItem('token'); // Obtener el token

    try {
        const response = await fetch('/products', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`, // Agregar el token en el encabezado
            },
        });

        if (!response.ok) {
            console.error('Error al cargar productos:', response.status, response.statusText);
            throw new Error('Error al cargar los productos');
        }

        const products = await response.json();
        const productsContainer = document.getElementById('products-container');
        productsContainer.innerHTML = "";

        products.forEach(product => {
            const productCard = `
                <div class="product-card" data-category="${product.categoria}">
                    <img src="${product.imagen}" alt="${product.nombre}" class="product-image">
                    <h3>${product.marca}</h3>
                    <p>${product.nombre}</p>
                    <p>Precio: $${product.precio.toLocaleString()}</p>
                    <p><strong>Droguería: ${product.drogueria}</strong></p>
                    <p><strong>Cantidad disponible: ${product.cantidad_disponible}</strong></p>
                    <button onclick="addToCart('${product.nombre}', ${product.precio}, '${product.drogueria}', '${product.imagen}')">Añadir a carrito</button>
                    <button onclick="buyProduct('${product.nombre}', ${product.precio}, '${product.drogueria}', '${product.imagen}')">Comprar</button>
                </div>
            `;
            productsContainer.insertAdjacentHTML('beforeend', productCard);
        });
    } catch (error) {
        console.error('Error al cargar productos:', error);
    }
}

// Función para cerrar sesión
function logout() {
    localStorage.removeItem('token'); // Eliminar el token del almacenamiento local
    window.location.href = 'login.html'; // Redirigir al inicio de sesión
}

// Agrega el evento al botón "Cerrar sesión"
document.getElementById('logout').addEventListener('click', logout);

// Función para abrir/cerrar el menú desplegable de categorías
function toggleDropdown() {
    var dropdown = document.getElementById("dropdown");
    dropdown.style.display = (dropdown.style.display === "block") ? "none" : "block";
}

// Función para abrir/cerrar el menú desplegable de cuenta
function toggleAccountDropdown() {
    var accountDropdown = document.getElementById("account-dropdown");
    accountDropdown.style.display = (accountDropdown.style.display === "block") ? "none" : "block";
}

// Cierra los dropdowns si se hace clic fuera de ellos
window.onclick = function (event) {
    var dropdown = document.getElementById('dropdown');
    var accountDropdown = document.getElementById('account-dropdown');

    if (!event.target.closest('.categories-btn') && dropdown.style.display === "block") {
        dropdown.style.display = "none";
    }

    if (!event.target.closest('.account-btn') && accountDropdown.style.display === "block") {
        accountDropdown.style.display = "none";
    }
}

// Función de filtrado por categoría
function filterByCategory(category) {
    const products = document.querySelectorAll('.product-card');
    products.forEach(product => {
        if (product.getAttribute('data-category') === category) {
            product.style.display = "block";
        } else {
            product.style.display = "none";
        }
    });
}

// Función de búsqueda de productos
function searchProducts() {
    let input = document.getElementById('search-input').value.toLowerCase();
    let products = document.querySelectorAll('.product-card');
    products.forEach(product => {
        let productName = product.querySelector('p').innerText.toLowerCase();
        let productBrand = product.querySelector('h3').innerText.toLowerCase();
        if (productName.includes(input) || productBrand.includes(input)) {
            product.style.display = "block";
        } else {
            product.style.display = "none";
        }
    });
}

// Función para abrir/cerrar el modal del carrito
function toggleCartModal() {
    var modal = document.getElementById('cart-modal');
    modal.style.display = (modal.style.display === "block") ? "none" : "block";
}

// Función para añadir productos al carrito
function addToCart(productName, productPrice, drogueria, productImage) {
    const existingProduct = cart.find(item => item.name === productName && item.price === productPrice);

    if (existingProduct) {
        existingProduct.quantity += 1; // Aumentar cantidad si ya existe
    } else {
        cart.push({ 
            name: productName, 
            price: productPrice, 
            quantity: 1, 
            drogueria, 
            imageUrl: productImage // Añadir la imagen al carrito
        });
        updateCartCount(); // Actualizar el contador solo al añadir un nuevo producto
    }

    renderCart();
}

// Nueva función para actualizar el contador del carrito
function updateCartCount() {
    const cartCountElement = document.getElementById("cart-count");
    const uniqueItems = cart.length; // Contar solo los productos únicos
    cartCountElement.innerText = uniqueItems; // Actualizar el texto del contador

    // Mostrar u ocultar el contador según el total
    if (uniqueItems > 0) {
        cartCountElement.style.display = "block";
    } else {
        cartCountElement.style.display = "none";
    }
}

// Función para modificar la cantidad de un producto
function updateQuantity(index, change) {
    if (cart[index].quantity + change >= 1) {
        cart[index].quantity += change;
    }
    renderCart();
}

// Función para eliminar productos del carrito
function removeFromCart(index) {
    cart.splice(index, 1);
    renderCart();
    updateCartCount(); // Actualizar el contador después de eliminar el producto
}

// Función para renderizar el carrito
function renderCart() {
    const cartTableBody = document.querySelector("#cart-table tbody");
    cartTableBody.innerHTML = ""; // Limpia el contenido anterior

    let total = 0; // Variable para almacenar el total

    cart.forEach((item, index) => {
        const subtotal = item.price * item.quantity;
        total += subtotal; // Sumar al total
        const row = `
            <tr>
                <td><img src="${item.imageUrl}" alt="${item.name}" class="cart-item-image" style="width: 50px;"></td>
                <td>${item.name}</td>
                <td>$${item.price.toLocaleString()}</td>
                <td>
                    <button class="quantity-btn" onclick="updateQuantity(${index}, -1)">-</button>
                    ${item.quantity}
                    <button class="quantity-btn" onclick="updateQuantity(${index}, 1)">+</button>
                </td>
                <td>$${subtotal.toLocaleString()}</td>
                <td>${item.drogueria}</td>
                <td><button class="delete-btn" onclick="removeFromCart(${index})">X</button></td>
            </tr>
        `;
        cartTableBody.insertAdjacentHTML("beforeend", row);
    });

    document.getElementById("total-price").innerText = `Total: $${total.toLocaleString()}`;

    // Agregar el botón de "Comprar productos" solo si hay productos en el carrito
    const cartModalContent = document.querySelector('.cart-modal-content');
    const existingBuyButton = cartModalContent.querySelector('.buy-button');
    
    if (cart.length > 0 && !existingBuyButton) {
        const buyButton = document.createElement('button');
        buyButton.classList.add('buy-button');
        buyButton.textContent = 'Comprar productos';
        buyButton.onclick = function() {
            // Guardar todos los productos en localStorage antes de ir a la página de pago
            localStorage.setItem('selectedProducts', JSON.stringify(cart));
            window.location.href = 'Pago.html'; // Redirige a la página de pago
        };

        cartModalContent.appendChild(buyButton);
    }
}

// Función para comprar un producto directamente (compra individual)
function buyProduct(productName, productPrice, drogueria, productImage) {
    // Verificar si hay más de un producto en el carrito
    if (cart.length > 1) {
        const confirmation = confirm(
            "Si compras este producto de manera individual, se eliminarán los otros productos del carrito. ¿Deseas continuar?"
        );

        // Si el usuario cancela, salir de la función
        if (!confirmation) {
            return;
        }
    }

    // Crea un objeto de producto con la información pasada como argumento
    const product = {
        name: productName,
        price: productPrice,
        quantity: 1, // Se asume una compra de una unidad para "Comprar"
        drogueria: drogueria,
        imageUrl: productImage // Añadir la imagen a la compra individual
    };

    // Guarda el producto en localStorage como un array para "selectedProducts"
    localStorage.setItem('selectedProducts', JSON.stringify([product]));

    // Redirige a la página de pago
    window.location.href = 'Pago.html';
}
