@app.get("/api/benchmark/results")
async def get_benchmark_results():
    """Get latest benchmark results"""
    try:
        csv_path = "data/benchmark_results.csv"
        if not os.path.exists(csv_path):
            return []
            
        df = pd.read_csv(csv_path)
        
        # Replace NaN with null for JSON compatibility
        df = df.replace({np.nan: None})
        
        return df.to_dict(orient='records')
    except Exception as e:
        logger.error(f"Error reading benchmark results: {e}")
        return []
