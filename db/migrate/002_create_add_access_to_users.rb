class CreateAddAccessToUsers < ActiveRecord::Migration[5.2]
  def change
    add_column :users, :access, :text
  end
end
