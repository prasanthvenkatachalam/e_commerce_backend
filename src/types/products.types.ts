export type Product = {
  id: string;
  category_id: string;
  name: string;
  slug: string;
  description?: string;
  base_price: number;
  sku_prefix?: string;
  sku?: string;
  images?: string[]; // Corrected to `string[] | undefined`
  is_active?: boolean;
  created_at: Date;
  updated_at?: Date;
  variants?: ProductVariant[];
};
  export type ProductVariant = {
    id: string;
    product_id: string;
    internal_sku: string;
    display_sku?: string;
    attributes?: { [key: string]: any };
    price_adjustment?: number;
    quantity?: number;
    low_stock_threshold?: number;
    optimal_stock?: number;
    weight?: number;
    dimensions?: { [key: string]: any };
    is_active: boolean;
    created_at: Date;
    updated_at?: Date;
  };