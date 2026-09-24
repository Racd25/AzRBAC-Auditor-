package main

import "fmt"

// addItems adds new items and their prices to the shopping list
func addItems(names []string, prices []float64, newNames []string, newPrices []float64) ([]string, []float64) {
	names = append(names, newNames...)
	prices = append(prices, newPrices...)
	return names, prices
}

// removeItem removes an item at the specified index
func removeItem(names []string, prices []float64, index int) ([]string, []float64) {

	for i, prices := range prices {
		if i == int(prices) {
			names = append(names[:i], names[i+1:]...)

		}

	}
	return names, prices
}

// findExpensiveItems returns items with prices above the threshold
func findExpensiveItems(names []string, prices []float64, threshold float64) []string {

	var limit []string
	for i, price := range prices {
		if price > threshold {
			limit = append(limit, names[i])
		}
	}
	return limit
}

// calculateTotalCost returns the sum of all prices
func calculateTotalCost(prices []float64) float64 {
	var total float64
	for _, prices := range prices {
		total += prices
	}
	return total
}

func main() {
	// Initialize empty shopping lists
	names := []string{}
	prices := []float64{}

	// Add initial items
	initialNames := []string{"Apples", "Milk", "Bread"}
	initialPrices := []float64{2.99, 3.49, 2.29}

	names, prices = addItems(names, prices, initialNames, initialPrices)

	// Print the initial shopping list
	fmt.Println("Initial Shopping List:")
	for i := range names {
		fmt.Printf("%d. %s - $%.2f\n", i, names[i], prices[i])
	}

	// Calculate and print total cost
	total := calculateTotalCost(prices)
	fmt.Printf("\nTotal Cost: $%.2f\n", total)

	// Find and print expensive items
	priceThreshold := 3.00
	expensiveItems := findExpensiveItems(names, prices, priceThreshold)

	fmt.Printf("\nExpensive Items (above $%.2f):\n", priceThreshold)
	for _, item := range expensiveItems {
		fmt.Println(item)
	}

	// Add a new item
	names, prices = addItems(names, prices, []string{"Cheese"}, []float64{4.99})

	// Remove an item
	names, prices = removeItem(names, prices, 1)
	fmt.Println("\nRemoved item at index 1")

	// Print the final shopping list
	fmt.Println("\nFinal Shopping List:")
	for i := range names {
		fmt.Printf("%d. %s - $%.2f\n", i, names[i], prices[i])
	}
}
